"""
nodes/sbom_node.py
==================
SBOM resolution for the SignedOff compliance agent.

Resolves the full Python dependency tree (direct + transitive) using
pipdeptree, fetches license metadata via pip-licenses, normalizes
license strings to SPDX identifiers, and produces a flat list of
PackageRecord objects ready for parallel License/CVE analysis.

V1 LIMITATION (intentional, surfaced in errors[]):
    pipdeptree reports the packages currently installed in the running
    venv — it does NOT install the submitted requirements file into an
    isolated env first. For the demo this is fine: the demo venv has
    `pip install -r demo_requirements.txt` pre-applied. v2 will install
    into a tempdir venv and run pipdeptree against that.

L1 cache contract:
    SBOMNode CHECKS the cache. LicenseNode/CVENode WRITE to the cache
    after fetching. A cache hit lets the downstream nodes skip the
    fetch entirely. cache_hits is surfaced in the sbom_resolved audit
    event to drive the demo's "X of Y from cache" UI metric.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import subprocess
from datetime import datetime, timezone
from typing import Optional

from agent_state import AgentState, PackageRecord


PIPDEPTREE_TIMEOUT_SECONDS = 60
PIP_LICENSES_TIMEOUT_SECONDS = 60


# pip-licenses returns human-readable strings; we map to SPDX identifiers.
# Keys are lowercased; the lookup also lowercases the input. Unknown strings
# pass through unchanged and are logged to errors[] so the SPDX list can be
# extended without losing the raw value.
LICENSE_NORMALIZATION: dict[str, Optional[str]] = {
    "mit": "MIT",
    "mit license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.1-or-later",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu affero general public license v3 (agpl-3.0)": "AGPL-3.0-only",
    "isc": "ISC",
    "isc license (iscl)": "ISC",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "python software foundation license": "Python-2.0",
    "lgpl": "LGPL-2.1-only",
    "unlicense": "Unlicense",
    "the unlicense (unlicense)": "Unlicense",
    "unknown": None,
    "": None,
}


def normalize_license(raw: Optional[str]) -> tuple[Optional[str], bool]:
    """
    Map a pip-licenses string to an SPDX identifier.

    Returns (value, recognized). If the input is in LICENSE_NORMALIZATION,
    returns (spdx_or_None, True). Otherwise returns (raw_string, False)
    so the caller can log a warning and the reviewer still sees what was
    reported.
    """
    if raw is None:
        return None, True
    key = raw.strip().lower()
    if key in LICENSE_NORMALIZATION:
        return LICENSE_NORMALIZATION[key], True
    return raw, False


# Recognizes the bare package name at the start of a requirements.txt line.
# Strips inline comments, blank lines, -r/-e/-c references, and VCS/URL installs.
_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")


def parse_direct_package_names(requirements_text: str) -> set[str]:
    """
    Extract the set of direct package names declared in a requirements file.

    Returns a set of LOWERCASED package names. PyPI names are case-insensitive,
    so casing the comparison set lets us match pipdeptree output regardless of
    how the user spelled the name.
    """
    direct: set[str] = set()
    for raw_line in requirements_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r", "-c", "-e", "--", "git+", "http://", "https://")):
            continue
        match = _REQUIREMENT_NAME_RE.match(line)
        if match:
            direct.add(match.group(1).lower())
    return direct


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sbom_resolved_event(total: int, direct: int, transitive: int, cache_hits: int) -> dict:
    return {
        "timestamp": _now_iso(),
        "event_type": "sbom_resolved",
        "payload": {
            "packages_total": total,
            "packages_direct": direct,
            "packages_transitive": transitive,
            "cache_hits": cache_hits,
        },
    }


def _sbom_failed_event(reason: str) -> dict:
    return {
        "timestamp": _now_iso(),
        "event_type": "sbom_failed",
        "payload": {"reason": reason},
    }


def _failure(reason: str, prior_errors: Optional[list[str]] = None) -> dict:
    errors = list(prior_errors or [])
    errors.append(reason)
    return {
        "raw_dependency_tree": {},
        "packages": [],
        "status": "failed",
        "audit_events": [_sbom_failed_event(reason)],
        "errors": errors,
    }


def _run_pipdeptree() -> list[dict]:
    completed = subprocess.run(
        ["pipdeptree", "--json-tree", "--warn", "silence"],
        capture_output=True,
        text=True,
        timeout=PIPDEPTREE_TIMEOUT_SECONDS,
        check=True,
    )
    return json.loads(completed.stdout)


def _run_pip_licenses() -> list[dict]:
    completed = subprocess.run(
        ["pip-licenses", "--format=json", "--with-license-file", "--no-license-path"],
        capture_output=True,
        text=True,
        timeout=PIP_LICENSES_TIMEOUT_SECONDS,
        check=True,
    )
    return json.loads(completed.stdout)


def _flatten_tree(tree: list[dict]) -> list[tuple[str, str, bool]]:
    """
    Walk a pipdeptree --json-tree result and yield (name, version, is_top_level)
    triples. is_top_level is the fallback for direct/transitive classification
    when no requirements file is available (repo_url path).
    """
    out: list[tuple[str, str, bool]] = []

    def walk(nodes: list[dict], depth: int) -> None:
        for node in nodes:
            name = node.get("package_name") or node.get("key") or ""
            version = node.get("installed_version") or ""
            if name and version:
                out.append((name, version, depth == 0))
            children = node.get("dependencies") or []
            if children:
                walk(children, depth + 1)

    walk(tree, 0)
    return out


def _try_get_l1_cache():
    try:
        from cache.l1_package_cache import l1_cache
        return l1_cache, None
    except Exception as exc:
        return None, f"L1 cache unavailable, continuing without cache: {exc}"


async def sbom_node(state: AgentState) -> dict:
    input_type = state.get("input_type", "")
    input_value = state.get("input_value", "")
    policy = state.get("policy") or {}
    include_transitive = bool(
        policy.get("scan_defaults", {}).get("include_transitive", True)
    )

    errors: list[str] = []
    direct_names: set[str] = set()

    if input_type == "requirements_file":
        try:
            decoded = base64.b64decode(input_value, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
            return _failure(f"input_value is not valid base64 UTF-8: {exc}")
        direct_names = parse_direct_package_names(decoded)
        if not direct_names:
            errors.append(
                "requirements file declared no recognizable direct packages; "
                "falling back to pipdeptree top-level entries for direct/transitive"
            )
    elif input_type == "repo_url":
        errors.append(
            "repo_url path is a v1 stub: dependencies are read from the running "
            "venv; direct/transitive classification falls back to pipdeptree "
            "tree position"
        )
    else:
        return _failure(f"unsupported input_type: {input_type!r}")

    errors.append(
        "v1 limitation: pipdeptree resolves the running venv, not an isolated "
        "install of the submitted requirements file"
    )

    try:
        tree = _run_pipdeptree()
    except subprocess.TimeoutExpired:
        return _failure("pipdeptree timed out", errors)
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        return _failure(f"pipdeptree failed (exit {exc.returncode}): {stderr}", errors)
    except FileNotFoundError:
        return _failure("pipdeptree is not installed in this environment", errors)
    except json.JSONDecodeError as exc:
        return _failure(f"pipdeptree returned non-JSON output: {exc}", errors)

    flat = _flatten_tree(tree)
    if not flat:
        return _failure("pipdeptree returned no packages", errors)

    license_by_name: dict[str, str] = {}
    try:
        for entry in _run_pip_licenses():
            pkg_name = (entry.get("Name") or "").lower()
            if pkg_name:
                license_by_name[pkg_name] = entry.get("License") or ""
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, json.JSONDecodeError) as exc:
        errors.append(f"pip-licenses unavailable, license=None for all packages: {exc}")

    l1_cache, cache_warning = _try_get_l1_cache()
    if cache_warning:
        errors.append(cache_warning)

    records: dict[str, PackageRecord] = {}
    cache_hits = 0
    has_explicit_direct_set = bool(direct_names)

    for name, version, is_top_level in flat:
        key = f"{name.lower()}=={version}"

        if has_explicit_direct_set:
            transitive = name.lower() not in direct_names
        else:
            transitive = not is_top_level

        if not include_transitive and transitive:
            continue

        if key in records:
            # Direct takes precedence on dedup: if we previously saw this as
            # transitive and now see it as direct, flip the flag.
            if not transitive and records[key]["transitive"]:
                records[key]["transitive"] = False
            continue

        raw_license = license_by_name.get(name.lower())
        spdx, recognized = normalize_license(raw_license)
        if not recognized:
            errors.append(
                f"license string for {name}=={version} not in SPDX map: {raw_license!r}"
            )

        record: PackageRecord = {
            "name": name,
            "version": version,
            "license": spdx,
            "license_status": None,
            "cves": [],
            "license_risk": None,
            "security_risk": None,
            "from_cache": False,
            "cached_at": None,
            "transitive": transitive,
        }

        if l1_cache is not None:
            cached = l1_cache.get(name, version)
            if cached:
                cache_hits += 1
                record["from_cache"] = True
                record["cached_at"] = cached.get("cached_at")
                if cached.get("license") is not None:
                    record["license"] = cached["license"]
                if cached.get("cves") is not None:
                    record["cves"] = cached["cves"]

        records[key] = record

    if not records:
        return _failure("no packages to scan after applying policy filters", errors)

    packages = list(records.values())
    total = len(packages)
    direct_count = sum(1 for p in packages if not p["transitive"])
    transitive_count = total - direct_count

    return {
        "raw_dependency_tree": {"tree": tree},
        "packages": packages,
        "status": "running",
        "audit_events": [
            _sbom_resolved_event(total, direct_count, transitive_count, cache_hits)
        ],
        "errors": errors,
    }
