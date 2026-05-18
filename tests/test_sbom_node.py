"""Tests for nodes.sbom_node — post-PyPI-rewrite (v1.1)."""

from __future__ import annotations

import asyncio
import base64
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cache.l1_package_cache import l1_cache  # noqa: E402
from nodes.sbom_node import (  # noqa: E402
    _detect_gpl_in_multi_license,
    _parse_classifier_to_license_string,
    _resolve_license_from_pypi,
    normalize_license,
    parse_direct_package_names,
    parse_requirements_with_versions,
    sbom_node,
)


def _run(coro):
    return asyncio.run(coro)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# PackageRecord-shape fixtures returned by the mocked PyPI resolver.
# These mimic what _resolve_packages_from_pypi() builds for the real
# code path, so the sbom_node test surface stays close to production.
# ---------------------------------------------------------------------------

def _pypi_record(name: str, version: str, license_id: str | None) -> dict:
    return {
        "name": name,
        "version": version,
        "license": license_id,
        "license_status": None,
        "cves": [],
        "license_risk": None,
        "security_risk": None,
        "from_cache": False,
        "cached_at": None,
        "transitive": False,
    }


DJANGO_REQUESTS_RECORDS = [
    _pypi_record("Django", "4.2.3", "BSD-3-Clause"),
    _pypi_record("requests", "2.31.0", "Apache-2.0"),
]


_NO_OVERRIDE = object()  # sentinel — distinguishes "default" from "[]"


def _patch_pypi(records=_NO_OVERRIDE, errors=_NO_OVERRIDE):
    """Patch _resolve_packages_from_pypi to a deterministic return value.
    Mirrors the spec's "function-level mock" guidance — avoids needing to
    mock aiohttp internals for every sbom_node integration test.

    Pass `records=[]` to simulate "every PyPI fetch failed" (the sentinel
    distinguishes that from the "use default" case)."""
    final_records = DJANGO_REQUESTS_RECORDS if records is _NO_OVERRIDE else records
    final_errors = [] if errors is _NO_OVERRIDE else errors
    return patch(
        "nodes.sbom_node._resolve_packages_from_pypi",
        new=AsyncMock(return_value=(final_records, final_errors)),
    )


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


# ---------------------------------------------------------------------------
# sbom_node — happy path + PackageRecord shape
# ---------------------------------------------------------------------------

def test_returns_normalized_package_records_with_full_typeddict_shape():
    with _patch_pypi():
        result = _run(sbom_node(_state()))

    assert result["status"] == "running"
    # PyPI-only resolution returns direct deps; demo state has django + requests.
    assert len(result["packages"]) == 2

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
        # All PyPI-resolved packages are direct (v1.1 scope).
        assert pkg["transitive"] is False

    sbom_event = next(
        e for e in result["audit_events"] if e["event_type"] == "sbom_resolved"
    )
    assert sbom_event["payload"]["packages_total"] == 2
    assert sbom_event["payload"]["packages_direct"] == 2
    assert sbom_event["payload"]["packages_transitive"] == 0
    assert sbom_event["payload"]["cache_hits"] == 0


def test_v1_1_limitation_surfaced_in_errors():
    """Every requirements_file scan surfaces the 'direct deps only' caveat
    so the UI and smoke tests can detect / display the v1.1 boundary."""
    with _patch_pypi():
        result = _run(sbom_node(_state()))
    assert any(
        "v1.1 limitation" in e and "direct dependencies" in e
        for e in result["errors"]
    ), f"v1.1 limitation note missing from errors: {result['errors']}"


def test_sbom_node_uses_pypi_not_subprocess():
    """The previous implementation shelled out to pipdeptree / pip-licenses
    against the server's running venv (BUGS.md ROOT CAUSE). Lock that the
    new implementation never touches subprocess for the SBOM path.

    This guards against a future refactor accidentally reintroducing the
    bug — anyone who adds a subprocess.run() call will trip this test."""
    import subprocess
    with patch("subprocess.run") as mock_run, _patch_pypi():
        _run(sbom_node(_state()))
    assert mock_run.call_count == 0, (
        f"sbom_node called subprocess.run {mock_run.call_count}x; "
        "the PyPI-based resolution must never shell out to pipdeptree/pip-licenses."
    )


# ---------------------------------------------------------------------------
# Dedup: requirements.txt can list the same package twice
# ---------------------------------------------------------------------------

def test_duplicate_requirement_lines_deduplicated():
    """PyYAML appears twice in demo_requirements.txt (pinned to the same
    version). The parser must deduplicate so a downstream PyPI call isn't
    wasted and the same package doesn't appear twice in the matrix."""
    parsed = parse_requirements_with_versions(
        "PyYAML==5.4.1\npyyaml==5.4.1\nrequests==2.31.0\n"
    )
    names = [n for n, _ in parsed]
    assert names == ["PyYAML", "requests"], parsed


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

def test_all_pypi_lookups_fail_marks_status_failed():
    """If every PyPI fetch fails (network down, registry returning 404
    for every name), there's nothing to scan. Treat as fatal."""
    with _patch_pypi(
        records=[],
        errors=["PyPI 404 for django==4.2.3", "PyPI 404 for requests==2.31.0"],
    ):
        result = _run(sbom_node(_state()))

    assert result["status"] == "failed"
    assert result["packages"] == []
    assert any(e["event_type"] == "sbom_failed" for e in result["audit_events"])
    # Fetch errors propagated.
    assert any("404" in e for e in result["errors"])


def test_empty_requirements_file_marks_status_failed():
    """A requirements file with only comments / blank lines / -r references
    has no parseable packages. Fail fast — there's nothing to scan."""
    requirements = "# just a comment\n\n-r other-reqs.txt\n"
    with _patch_pypi():
        result = _run(sbom_node(_state(requirements=requirements)))
    assert result["status"] == "failed"


def test_invalid_base64_input_marks_status_failed():
    state = _state()
    state["input_value"] = "!!!not-base64!!!"
    with _patch_pypi():
        result = _run(sbom_node(state))
    assert result["status"] == "failed"
    assert any("base64" in e.lower() for e in result["errors"])


def test_unsupported_input_type_marks_status_failed():
    state = _state()
    state["input_type"] = "repo_url"
    with _patch_pypi():
        result = _run(sbom_node(state))
    assert result["status"] == "failed"


# ---------------------------------------------------------------------------
# L1 cache integration — cache check runs AFTER record construction
# ---------------------------------------------------------------------------

def test_l1_cache_hit_increments_counter_and_populates_record():
    """Cache check happens in sbom_node after _resolve_packages_from_pypi
    returns. Mocking the PyPI resolver still exercises the cache logic."""
    l1_cache.set("Django", "4.2.3", license="BSD-3-Clause", cves=[{"id": "CVE-test"}])

    with _patch_pypi():
        result = _run(sbom_node(_state()))

    sbom_event = next(
        e for e in result["audit_events"] if e["event_type"] == "sbom_resolved"
    )
    assert sbom_event["payload"]["cache_hits"] == 1

    django = next(p for p in result["packages"] if p["name"].lower() == "django")
    assert django["from_cache"] is True
    assert django["cached_at"] is not None
    assert django["cves"] == [{"id": "CVE-test"}]


# ---------------------------------------------------------------------------
# include_transitive policy flag
# ---------------------------------------------------------------------------

def test_include_transitive_false_does_not_drop_direct_packages():
    """The PyPI rewrite doesn't include transitive packages at all (v1.1
    scope). The include_transitive policy flag becomes a no-op for direct
    deps — all packages from requirements.txt are direct, so all pass
    through regardless of the flag."""
    policy = {
        "scan_defaults": {"include_transitive": False},
        "policy_hash": "test",
    }
    with _patch_pypi():
        result = _run(sbom_node(_state(policy=policy)))

    assert result["status"] == "running"
    names = {p["name"].lower() for p in result["packages"]}
    assert names == {"django", "requests"}
    assert all(p["transitive"] is False for p in result["packages"])


# ---------------------------------------------------------------------------
# parse_requirements_with_versions — edge cases
# ---------------------------------------------------------------------------

def test_parse_requirements_with_versions_pinned():
    parsed = parse_requirements_with_versions(
        "django==4.2.3\nrequests==2.28.0\n"
    )
    assert parsed == [("django", "4.2.3"), ("requests", "2.28.0")]


def test_parse_requirements_with_versions_unpinned():
    parsed = parse_requirements_with_versions("django>=4.0\nflask\n")
    assert parsed == [("django", None), ("flask", None)]


def test_parse_requirements_with_versions_extras_and_comments():
    parsed = parse_requirements_with_versions(
        "requests[security]==2.28.0\n# comment\n-r other.txt\n"
    )
    assert parsed == [("requests", "2.28.0")]


def test_parse_requirements_with_versions_deduplicates():
    """First occurrence wins. Dedup is case-insensitive (PyPI names are
    case-insensitive)."""
    parsed = parse_requirements_with_versions(
        "PyYAML==5.4.1\nPyYAML==5.4.1\npyyaml==99.9.9\n"
    )
    assert parsed == [("PyYAML", "5.4.1")]


def test_parse_requirements_with_versions_skips_url_and_vcs_installs():
    """git+/http(s)/local-file refs aren't normal name==version specs;
    we ignore them rather than guess. They'll surface in errors[] only
    if a fully-named line is also missing."""
    parsed = parse_requirements_with_versions(
        "django==4.2.3\n"
        "git+https://github.com/foo/bar.git\n"
        "http://example.com/pkg.tar.gz\n"
        "-e ./local-package\n"
    )
    assert parsed == [("django", "4.2.3")]


# ---------------------------------------------------------------------------
# _fetch_pypi_metadata — direct aiohttp-level error handling
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status: int, payload: dict | None = None):
        self.status = status
        self._payload = payload or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, response):
        self._response = response

    def get(self, url):
        return self._response


def test_fetch_pypi_metadata_success():
    from nodes.sbom_node import _fetch_pypi_metadata
    fixture = {
        "info": {
            "name": "Django",
            "version": "4.2.3",
            "license": "BSD-3-Clause",
            "classifiers": [
                "License :: OSI Approved :: BSD License",
                "Programming Language :: Python :: 3",
            ],
        }
    }
    sem = asyncio.Semaphore(1)
    session = _FakeSession(_FakeResponse(200, fixture))
    r = _run(_fetch_pypi_metadata(session, sem, "Django", "4.2.3"))
    assert r["success"] is True
    assert r["error"] is None
    assert r["name"] == "Django"
    assert r["version"] == "4.2.3"
    assert r["license_raw"] == "BSD-3-Clause"
    assert r["license_classifiers"] == ["License :: OSI Approved :: BSD License"]


def test_fetch_pypi_metadata_404():
    from nodes.sbom_node import _fetch_pypi_metadata
    sem = asyncio.Semaphore(1)
    session = _FakeSession(_FakeResponse(404))
    r = _run(_fetch_pypi_metadata(session, sem, "no-such-pkg", "1.0"))
    assert r["success"] is False
    assert "404" in (r["error"] or "")


def test_fetch_pypi_metadata_timeout():
    from nodes.sbom_node import _fetch_pypi_metadata

    class _TimingOutSession:
        def get(self, url):
            class _Ctx:
                async def __aenter__(self):
                    raise asyncio.TimeoutError()
                async def __aexit__(self, *_):
                    return False
            return _Ctx()

    sem = asyncio.Semaphore(1)
    r = _run(_fetch_pypi_metadata(_TimingOutSession(), sem, "django", "4.2.3"))
    assert r["success"] is False
    assert "timeout" in (r["error"] or "").lower()


# ---------------------------------------------------------------------------
# _resolve_license_from_pypi — the priority chain
# ---------------------------------------------------------------------------

def test_resolve_license_clean_field():
    assert _resolve_license_from_pypi("MIT", []) == "MIT"


def test_resolve_license_empty_field_classifier_fallback():
    assert _resolve_license_from_pypi(
        "", ["License :: OSI Approved :: MIT License"]
    ) == "MIT"


def test_resolve_license_full_text_classifier_fallback():
    """When info.license contains a multi-KB blob of the license text,
    the >100-char guard kicks in and the classifier provides the
    answer."""
    huge_blob = "BSD 3-Clause License\n\n" + ("x" * 2000)
    assert _resolve_license_from_pypi(
        huge_blob, ["License :: OSI Approved :: BSD License"]
    ) == "BSD-3-Clause"


def test_resolve_license_multi_license_or():
    """The compliance-safe GPL detection runs through normalize_license
    first; for permissive OR permissive, the map handles it."""
    assert _resolve_license_from_pypi("Apache-2.0 OR MIT", []) == "Apache-2.0"


def test_resolve_license_returns_raw_when_unrecognized():
    """If neither the field nor any classifier matches, fall back to the
    raw string so LicenseNode can flag it as 'unknown' with the actual
    text visible (better debugging than just None)."""
    assert _resolve_license_from_pypi(
        "Some Bespoke Internal License", []
    ) == "Some Bespoke Internal License"


def test_resolve_license_returns_none_when_nothing():
    assert _resolve_license_from_pypi("", []) is None
    assert _resolve_license_from_pypi(None, []) is None


# ---------------------------------------------------------------------------
# Classifier parser
# ---------------------------------------------------------------------------

def test_parse_classifier_extracts_last_segment():
    assert _parse_classifier_to_license_string(
        "License :: OSI Approved :: MIT License"
    ) == "MIT License"
    assert _parse_classifier_to_license_string(
        "License :: OSI Approved :: BSD License"
    ) == "BSD License"


def test_parse_classifier_handles_single_segment():
    assert _parse_classifier_to_license_string("MIT License") == "MIT License"


# ---------------------------------------------------------------------------
# SPDX normalization regressions for the spec's new map entries
# ---------------------------------------------------------------------------

def test_hpnd_normalization():
    assert normalize_license("HPND") == ("HPND", True)
    assert normalize_license(
        "Historical Permission Notice and Disclaimer (HPND)"
    ) == ("HPND", True)


def test_lgpl_with_exceptions_normalization():
    assert normalize_license("LGPL with exceptions") == ("LGPL-2.1-or-later", True)


def test_apache_or_mit_normalization():
    """Maps the canonical 'Apache-2.0 OR MIT' to the more conservative
    Apache reading (existing map convention for permissive-OR-permissive
    strings)."""
    assert normalize_license("Apache-2.0 OR MIT") == ("Apache-2.0", True)


def test_bsd3_or_apache_normalization():
    assert normalize_license("BSD-3-Clause OR Apache-2.0") == (
        "BSD-3-Clause", True,
    )


# ---------------------------------------------------------------------------
# Pre-existing normalization + GPL detection tests (still valid)
# ---------------------------------------------------------------------------

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

    unknown_value, unknown_recognized = normalize_license("Some Custom License")
    assert unknown_value == "Some Custom License"
    assert unknown_recognized is False

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


def test_normalization_handles_real_world_pip_licenses_strings():
    cases = [
        ("Apache License 2.0", "Apache-2.0"),
        ("Apache Software License; BSD License", "Apache-2.0"),
        ("Apache Software License; MIT License", "Apache-2.0"),
        ("Apache-2.0 AND MIT", "Apache-2.0"),
        ("Apache-2.0 OR BSD-2-Clause", "Apache-2.0"),
        ("BSD 3-Clause OR Apache-2.0", "BSD-3-Clause"),
        ("MIT OR Apache-2.0", "MIT"),
        ("MIT-CMU", "MIT"),
        ("PSF-2.0", "Python-2.0"),
    ]
    for raw, expected in cases:
        spdx, recognized = normalize_license(raw)
        assert recognized, f"{raw!r} should be recognized; got ({spdx!r}, False)"
        assert spdx == expected, f"{raw!r} → {spdx!r}, expected {expected!r}"


def test_artistic_plus_gpl_plus_gplv2plus_detected_as_gpl_2_or_later():
    raw = ("Artistic License; GNU General Public License (GPL); "
           "GNU General Public License v2 or later (GPLv2+)")
    assert _detect_gpl_in_multi_license(raw) == "GPL-2.0-or-later"
    spdx, recognized = normalize_license(raw)
    assert spdx == "GPL-2.0-or-later"
    assert recognized is True


def test_apache_plus_gpl_plus_lgpl_does_not_hide_gpl():
    raw = ("Apache Software License; GNU General Public License (GPL); "
           "GNU Library or Lesser General Public License (LGPL)")
    detected = _detect_gpl_in_multi_license(raw)
    assert detected is not None, "LGPL co-listing must not mask the GPL mention"
    assert detected.startswith("GPL-"), f"expected GPL family, got {detected}"


def test_pure_lgpl_does_not_trigger_gpl_detection():
    assert _detect_gpl_in_multi_license("LGPL-2.1-only") is None
    assert _detect_gpl_in_multi_license("GNU Lesser General Public License (LGPL)") is None
    assert _detect_gpl_in_multi_license(
        "GNU Library or Lesser General Public License (LGPL)"
    ) is None


def test_agpl_always_detected_even_single_license():
    assert _detect_gpl_in_multi_license("AGPL-3.0-only") == "AGPL-3.0-or-later"
    assert _detect_gpl_in_multi_license("AGPL-3.0-or-later") == "AGPL-3.0-or-later"
    assert _detect_gpl_in_multi_license(
        "GNU Affero General Public License v3"
    ) == "AGPL-3.0-or-later"

    spdx, recognized = normalize_license("AGPL-3.0-only")
    assert recognized is True
    assert spdx == "AGPL-3.0-or-later"


def test_single_license_gplv2_still_maps_precisely_via_normalization_map():
    spdx, recognized = normalize_license("GNU General Public License v2 (GPLv2)")
    assert recognized is True
    assert spdx == "GPL-2.0-only"


def test_gpl_v3_detected_from_multi_license():
    raw = "MIT; GNU General Public License v3 (GPLv3)"
    assert _detect_gpl_in_multi_license(raw) == "GPL-3.0-or-later"


def test_generic_gpl_in_multi_license_assumes_most_restrictive():
    raw = "MIT; GNU General Public License (GPL)"
    assert _detect_gpl_in_multi_license(raw) == "GPL-3.0-or-later"
