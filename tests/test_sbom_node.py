"""Tests for nodes.sbom_node."""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cache.l1_package_cache import l1_cache  # noqa: E402
from nodes.sbom_node import (  # noqa: E402
    normalize_license,
    parse_direct_package_names,
    sbom_node,
)


def _run(coro):
    return asyncio.run(coro)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# Fixtures -------------------------------------------------------------------

PIPDEPTREE_FIXTURE = [
    {
        "key": "django",
        "package_name": "Django",
        "installed_version": "4.2.3",
        "dependencies": [
            {
                "key": "asgiref",
                "package_name": "asgiref",
                "installed_version": "3.7.2",
                "dependencies": [],
            },
            {
                "key": "sqlparse",
                "package_name": "sqlparse",
                "installed_version": "0.4.4",
                "dependencies": [],
            },
        ],
    },
    {
        "key": "requests",
        "package_name": "requests",
        "installed_version": "2.31.0",
        "dependencies": [
            {
                "key": "urllib3",
                "package_name": "urllib3",
                "installed_version": "2.0.7",
                "dependencies": [],
            },
        ],
    },
    {
        "key": "asgiref",
        "package_name": "asgiref",
        "installed_version": "3.7.2",
        "dependencies": [],
    },
]

PIP_LICENSES_FIXTURE = [
    {"Name": "Django", "Version": "4.2.3", "License": "BSD License"},
    {"Name": "asgiref", "Version": "3.7.2", "License": "BSD License"},
    {"Name": "sqlparse", "Version": "0.4.4", "License": "BSD License"},
    {"Name": "requests", "Version": "2.31.0", "License": "Apache 2.0"},
    {"Name": "urllib3", "Version": "2.0.7", "License": "MIT License"},
]


def _fake_subprocess(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args")
    if cmd[0] == "pipdeptree":
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=json.dumps(PIPDEPTREE_FIXTURE), stderr=""
        )
    if cmd[0] == "pip-licenses":
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=json.dumps(PIP_LICENSES_FIXTURE), stderr=""
        )
    raise AssertionError(f"unexpected command: {cmd}")


def _state(requirements: str = "django==4.2.3\nrequests==2.31.0\n",
           policy: dict | None = None) -> dict:
    return {
        "job_id": "job-test",
        "input_type": "requirements_file",
        "input_value": _b64(requirements),
        "use_case": "saas",
        "policy": policy or {
            "scan_defaults": {"include_transitive": True},
            "policy_hash": "test",
        },
    }


def setup_function(_):
    l1_cache.clear()


# Tests ----------------------------------------------------------------------

def test_returns_normalized_package_records_with_full_typeddict_shape():
    with patch("nodes.sbom_node.subprocess.run", side_effect=_fake_subprocess):
        result = _run(sbom_node(_state()))

    assert result["status"] == "running"
    assert len(result["packages"]) == 5

    expected_fields = {
        "name", "version", "license", "license_status", "cves",
        "license_risk", "security_risk", "from_cache", "cached_at", "transitive",
    }
    for pkg in result["packages"]:
        assert set(pkg.keys()) == expected_fields, (
            f"PackageRecord for {pkg.get('name')!r} has unexpected keys"
        )
        assert pkg["cves"] == []
        assert pkg["license_status"] is None
        assert pkg["license_risk"] is None
        assert pkg["security_risk"] is None
        assert pkg["from_cache"] is False  # no L1 hits in this test

    sbom_event = next(
        e for e in result["audit_events"] if e["event_type"] == "sbom_resolved"
    )
    assert sbom_event["payload"]["packages_total"] == 5
    assert sbom_event["payload"]["packages_direct"] == 2  # django + requests
    assert sbom_event["payload"]["packages_transitive"] == 3
    assert sbom_event["payload"]["cache_hits"] == 0


def test_deduplicates_direct_and_transitive_with_direct_winning():
    # asgiref appears twice in pipdeptree (transitive of django, top-level entry).
    # When listed in requirements, it should appear ONCE with transitive=False.
    requirements = "django==4.2.3\nrequests==2.31.0\nasgiref==3.7.2\n"
    with patch("nodes.sbom_node.subprocess.run", side_effect=_fake_subprocess):
        result = _run(sbom_node(_state(requirements=requirements)))

    asgiref_records = [p for p in result["packages"] if p["name"].lower() == "asgiref"]
    assert len(asgiref_records) == 1
    assert asgiref_records[0]["transitive"] is False


def test_spdx_normalization_for_common_license_strings():
    cases = [
        ("MIT", "MIT"),
        ("MIT License", "MIT"),
        ("Apache 2.0", "Apache-2.0"),
        ("Apache Software License", "Apache-2.0"),
        ("BSD License", "BSD-3-Clause"),
        ("BSD 2-Clause", "BSD-2-Clause"),
        ("GNU General Public License v2 (GPLv2)", "GPL-2.0-only"),
        ("GNU Lesser General Public License v2 or later (LGPLv2+)", "LGPL-2.1-or-later"),
        ("ISC License (ISCL)", "ISC"),
        ("Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0"),
    ]
    for raw, expected in cases:
        spdx, recognized = normalize_license(raw)
        assert recognized, f"{raw!r} should be recognized"
        assert spdx == expected, f"{raw!r} → {spdx!r}, expected {expected!r}"

    # Unknown strings pass through with recognized=False
    unknown_value, unknown_recognized = normalize_license("Some Custom License")
    assert unknown_value == "Some Custom License"
    assert unknown_recognized is False

    # Explicit empty / unknown / None sentinels collapse to None, recognized=True
    assert normalize_license("Unknown") == (None, True)
    assert normalize_license("") == (None, True)
    assert normalize_license(None) == (None, True)


def test_parse_direct_package_names_handles_common_formats():
    text = """
# comment line, ignored
django==4.2.3
requests>=2.0
flask
flask-cors[extra]==1.0
-r other.txt
git+https://github.com/foo/bar
"""
    direct = parse_direct_package_names(text)
    assert direct == {"django", "requests", "flask", "flask-cors"}


def test_pipdeptree_failure_marks_status_failed():
    def boom(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args")
        if cmd[0] == "pipdeptree":
            raise subprocess.CalledProcessError(
                returncode=1, cmd=cmd, output="", stderr="boom"
            )
        return _fake_subprocess(*args, **kwargs)

    with patch("nodes.sbom_node.subprocess.run", side_effect=boom):
        result = _run(sbom_node(_state()))

    assert result["status"] == "failed"
    assert result["packages"] == []
    assert any(e["event_type"] == "sbom_failed" for e in result["audit_events"])


def test_l1_cache_hit_increments_counter_and_populates_record():
    l1_cache.set("Django", "4.2.3", license="BSD-3-Clause", cves=[{"id": "CVE-test"}])

    with patch("nodes.sbom_node.subprocess.run", side_effect=_fake_subprocess):
        result = _run(sbom_node(_state()))

    sbom_event = next(
        e for e in result["audit_events"] if e["event_type"] == "sbom_resolved"
    )
    assert sbom_event["payload"]["cache_hits"] == 1

    django = next(p for p in result["packages"] if p["name"].lower() == "django")
    assert django["from_cache"] is True
    assert django["cached_at"] is not None
    assert django["cves"] == [{"id": "CVE-test"}]


def test_include_transitive_false_filters_out_indirect_packages():
    policy = {
        "scan_defaults": {"include_transitive": False},
        "policy_hash": "test",
    }
    with patch("nodes.sbom_node.subprocess.run", side_effect=_fake_subprocess):
        result = _run(sbom_node(_state(policy=policy)))

    assert result["status"] == "running"
    names = {p["name"].lower() for p in result["packages"]}
    assert names == {"django", "requests"}
    assert all(p["transitive"] is False for p in result["packages"])
