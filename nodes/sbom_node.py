"""
nodes/sbom_node.py
==================
SBOM resolution for the SignedOff compliance agent.

Parses the uploaded requirements.txt, queries the PyPI JSON API for each
package's metadata, normalizes license strings to SPDX identifiers, and
produces a flat list of PackageRecord objects ready for parallel
License/CVE analysis.

V1.1 LIMITATION (intentional, surfaced in errors[]):
    Only DIRECT dependencies declared in requirements.txt are resolved.
    Transitive dependencies are NOT included because the PyPI JSON API
    provides dependency names (requires_dist) but not fully resolved
    versions. Full transitive resolution requires pip's dependency
    resolver. v2 will add this via pip-compile dry-run or resolvelib.

Why PyPI instead of pipdeptree:
    The previous implementation shelled out to `pipdeptree` and
    `pip-licenses`. Both introspect the *running* Python environment —
    on a hosted server (Render) that's the server's own venv, NOT the
    user's uploaded requirements.txt. The result was findings for
    SignedOff's own dependencies attributed to the user's repo. The
    PyPI JSON API resolves package metadata directly from the
    public registry — independent of the server's installed packages.
    See BUGS.md "ROOT CAUSE - SBOMNode scans the server's own venv".

L1 cache contract:
    SBOMNode CHECKS the cache. LicenseNode/CVENode WRITE to the cache
    after fetching. A cache hit lets the downstream nodes skip the
    fetch entirely. cache_hits is surfaced in the sbom_resolved audit
    event to drive the demo's "X of Y from cache" UI metric.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
from datetime import datetime, timezone
from typing import Optional

from agent_state import AgentState, PackageRecord


PYPI_BASE_URL = "https://pypi.org/pypi"
PYPI_TIMEOUT_SECONDS = 15
PYPI_CONCURRENCY = 10


# pip-licenses returns human-readable strings; we map to SPDX identifiers.
# Keys are lowercased; the lookup also lowercases the input. Unknown strings
# pass through unchanged and are logged to errors[] so the SPDX list can be
# extended without losing the raw value.
LICENSE_NORMALIZATION: dict[str, Optional[str]] = {
    "mit": "MIT",
    "mit license": "MIT",
    "mit-cmu": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache software license; bsd license": "Apache-2.0",
    "apache software license; mit license": "Apache-2.0",
    "apache-2.0 and mit": "Apache-2.0",
    "apache-2.0 or bsd-2-clause": "Apache-2.0",
    "apache-2.0 or mit": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause or apache-2.0": "BSD-3-Clause",
    "bsd-3-clause or apache-2.0": "BSD-3-Clause",
    "mit or apache-2.0": "MIT",
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
    "psf-2.0": "Python-2.0",
    "lgpl": "LGPL-2.1-only",
    "lgpl with exceptions": "LGPL-2.1-or-later",
    "hpnd": "HPND",
    "historical permission notice and disclaimer (hpnd)": "HPND",
    "unlicense": "Unlicense",
    "the unlicense (unlicense)": "Unlicense",
    "unknown": None,
    "": None,
}


def _detect_gpl_in_multi_license(license_str: str) -> Optional[str]:
    """
    Compliance-safe GPL detection.

    Returns the most-restrictive GPL SPDX identifier we can infer, or None
    if no GPL-family license is present. Reasoning:

      - If a license declaration mentions GPL alongside permissive options
        (e.g. "Apache; GPL; LGPL"), a downstream recipient could choose
        to receive it under GPL terms — which triggers copyleft regardless
        of the other available licenses. Compliance-safe interpretation
        wins.

      - AGPL is always returned, even on single-license inputs — it's
        network-copyleft and severe enough that the conservative reading
        ("AGPL-3.0-or-later") is warranted even for "AGPL-3.0-only".

      - Other GPL variants ONLY return a value for multi-license strings
        (containing ";" or " or " separators). Single-license inputs like
        "GPLv2" fall through to the explicit normalization map so precise
        variants (e.g. "GPL-2.0-only" vs "GPL-2.0-or-later") are preserved.

      - Pure LGPL declarations are NOT GPL — return None so the map handles
        the LGPL-specific mapping.
    """
    s = license_str.lower()

    # AGPL: always trigger. Substring check has to come BEFORE the GPL-3
    # check below, since "agpl-3" contains "gpl-3".
    if "agpl" in s or "affero" in s:
        return "AGPL-3.0-or-later"

    # Other GPL variants only get the conservative reading on multi-license
    # declarations. Single-license inputs use the precise map.
    is_multi = ";" in s or " or " in s
    if not is_multi:
        return None

    # LGPL exclusion: if the only "GPL" mentions are inside "LGPL" /
    # "Library or Lesser General Public" / "Lesser General Public", treat
    # as pure LGPL and let the map handle it.
    has_lgpl = (
        "lgpl" in s
        or "lesser general public" in s
        or "library or lesser" in s
    )
    if has_lgpl:
        stripped = (
            s.replace("lgpl", "")
            .replace("library or lesser general public", "")
            .replace("lesser general public", "")
        )
        if "gpl" not in stripped and "general public" not in stripped:
            return None

    if any(t in s for t in ("gplv3", "gpl v3", "gpl-3", "gpl3")):
        return "GPL-3.0-or-later"
    if any(t in s for t in ("gplv2", "gpl v2", "gpl-2", "gpl2")):
        return "GPL-2.0-or-later"

    # Generic GPL mention with no version → assume most restrictive.
    if "gpl" in s or "general public license" in s:
        return "GPL-3.0-or-later"

    return None


def normalize_license(raw: Optional[str]) -> tuple[Optional[str], bool]:
    """
    Map a license string to an SPDX identifier.

    Returns (value, recognized). Order of operations:
      1. None / empty / "unknown" sentinel → (None, True).
      2. Compliance-safe GPL detection — runs BEFORE map lookup so any
         multi-license string containing GPL gets the conservative SPDX
         identifier (and so AGPL is caught regardless of phrasing).
      3. Explicit map lookup for precise single-license mapping.
      4. Otherwise return (raw, False) so the caller can log a warning.
    """
    if raw is None:
        return None, True
    key = raw.strip().lower()
    if key in ("", "unknown"):
        return None, True

    gpl_detected = _detect_gpl_in_multi_license(raw)
    if gpl_detected:
        return gpl_detected, True

    if key in LICENSE_NORMALIZATION:
        return LICENSE_NORMALIZATION[key], True
    return raw, False


# Recognizes the bare package name at the start of a requirements.txt line.
# Strips inline comments, blank lines, -r/-e/-c references, and VCS/URL installs.
_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")

# Captures (name, pinned_version_or_None) from a single requirements line.
# Handles optional [extras] block and == pin. Other version operators
# (>=, >, <=, ~=, !=) leave version as None.
_REQUIREMENT_WITH_VERSION_RE = re.compile(
    r"^\s*"
    r"([A-Za-z0-9][A-Za-z0-9_.\-]*)"   # name
    r"(?:\[[^\]]*\])?"                 # optional [extras]
    r"\s*"
    r"(?:==\s*([A-Za-z0-9_.\-+]+))?"   # optional ==version
)


def parse_direct_package_names(requirements_text: str) -> set[str]:
    """
    Extract the set of direct package names declared in a requirements file.

    Returns a set of LOWERCASED package names. PyPI names are case-insensitive,
    so casing the comparison set lets us match registry output regardless of
    how the user spelled the name.

    Kept for backward compatibility (importers and tests). The main
    requirements_file path uses parse_requirements_with_versions() instead.
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


def parse_requirements_with_versions(
    requirements_text: str,
) -> list[tuple[str, Optional[str]]]:
    """
    Extract (package_name, pinned_version_or_None) from requirements text.

    Handles: == pins (captured), >=/>/<=/~=/!= constraints (name only),
    [extras] syntax, comments, blank lines, -r/-c/-e/--/git+/http lines.
    Deduplicates by lowercased name, first occurrence wins.

    Returns list of (name, version) tuples in source order. version is
    None if not == pinned.
    """
    seen_lower: set[str] = set()
    out: list[tuple[str, Optional[str]]] = []
    for raw_line in requirements_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r", "-c", "-e", "--", "git+", "http://", "https://")):
            continue
        m = _REQUIREMENT_WITH_VERSION_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        if name.lower() in seen_lower:
            continue
        seen_lower.add(name.lower())
        version = m.group(2)  # None when not == pinned
        out.append((name, version))
    return out


def _parse_classifier_to_license_string(classifier: str) -> str:
    """
    Extract license name from a PyPI trove classifier.

    "License :: OSI Approved :: MIT License" -> "MIT License"
    "License :: OSI Approved :: BSD License" -> "BSD License"

    Takes the last segment after " :: " splitting. Trailing/leading
    whitespace is stripped. Caller passes the result to
    normalize_license() to get an SPDX identifier.
    """
    parts = [p.strip() for p in classifier.split("::")]
    return parts[-1] if parts else classifier.strip()


def _resolve_license_from_pypi(
    license_raw: Optional[str],
    license_classifiers: list[str],
) -> Optional[str]:
    """
    Best-effort SPDX license from PyPI metadata.

    Algorithm:
      1. license_raw non-empty AND len <= 100 -> normalize_license().
         If recognized, return it.
      2. Otherwise try first License :: classifier via
         _parse_classifier_to_license_string() -> normalize_license().
         If recognized, return it.
      3. Fallback: return license_raw verbatim if it exists (the
         LicenseNode downstream will treat unrecognized strings as
         "unknown" — preserving the raw signal is still useful for
         audit / debugging).
      4. Otherwise None.

    The len <= 100 guard is for packages like django-admin-interface or
    pytest-django that paste their full license text into info.license
    (kilobyte-sized strings). normalize_license() can't make sense of
    those; the classifier fallback usually has a clean signal.
    """
    if license_raw and len(license_raw) <= 100:
        spdx, recognized = normalize_license(license_raw)
        if recognized and spdx is not None:
            return spdx

    if license_classifiers:
        parsed = _parse_classifier_to_license_string(license_classifiers[0])
        spdx, recognized = normalize_license(parsed)
        if recognized and spdx is not None:
            return spdx

    if license_raw:
        return license_raw
    return None


async def _fetch_pypi_metadata(
    session,
    sem: asyncio.Semaphore,
    name: str,
    version: Optional[str],
) -> dict:
    """
    Query the PyPI JSON API for a single package.

    Pinned:   GET https://pypi.org/pypi/{name}/{version}/json
    Unpinned: GET https://pypi.org/pypi/{name}/json (returns latest)

    Returns dict with keys:
      name (str), version (str), license_raw (str), license_classifiers
      (list[str]), success (bool), error (Optional[str]).

    Never raises. HTTP 404, timeouts, and connection errors all return
    success=False with an explanatory `error` string. The orchestrator
    aggregates these into the node's errors[] output.
    """
    if version:
        url = f"{PYPI_BASE_URL}/{name}/{version}/json"
    else:
        url = f"{PYPI_BASE_URL}/{name}/json"

    async with sem:
        try:
            async with session.get(url) as resp:
                if resp.status == 404:
                    return {
                        "name": name,
                        "version": version or "",
                        "license_raw": "",
                        "license_classifiers": [],
                        "success": False,
                        "error": f"PyPI 404 for {name}{f'=={version}' if version else ''}",
                    }
                if resp.status != 200:
                    return {
                        "name": name,
                        "version": version or "",
                        "license_raw": "",
                        "license_classifiers": [],
                        "success": False,
                        "error": f"PyPI HTTP {resp.status} for {name}",
                    }
                payload = await resp.json()
        except asyncio.TimeoutError:
            return {
                "name": name,
                "version": version or "",
                "license_raw": "",
                "license_classifiers": [],
                "success": False,
                "error": f"PyPI timeout fetching {name}",
            }
        except Exception as exc:  # connection error, DNS, malformed JSON
            return {
                "name": name,
                "version": version or "",
                "license_raw": "",
                "license_classifiers": [],
                "success": False,
                "error": f"PyPI fetch failed for {name}: {exc}",
            }

    info = payload.get("info") or {}
    pypi_name = info.get("name") or name
    pypi_version = info.get("version") or version or ""
    license_raw = (info.get("license") or "").strip()
    classifiers = info.get("classifiers") or []
    license_classifiers = [
        c for c in classifiers if isinstance(c, str) and c.startswith("License ::")
    ]

    return {
        "name": pypi_name,
        "version": pypi_version,
        "license_raw": license_raw,
        "license_classifiers": license_classifiers,
        "success": True,
        "error": None,
    }


async def _resolve_packages_from_pypi(
    parsed_requirements: list[tuple[str, Optional[str]]],
) -> tuple[list[dict], list[str]]:
    """
    Fetch metadata from PyPI for all packages, build PackageRecord list.

    Uses asyncio.Semaphore(PYPI_CONCURRENCY) + a shared aiohttp.ClientSession.
    Mirrors the concurrency pattern in cve_node._enrich_vulns().

    Returns (records, errors):
      records — list of PackageRecord dicts (one per successful fetch).
                transitive=False on every record (v1.1 scope).
                from_cache=False, cached_at=None — L1 cache check runs
                in the caller AFTER record construction so that mocking
                this function in tests keeps the cache logic exercised.
      errors  — list of human-readable error strings for failed fetches.
                The orchestrator surfaces these via state["errors"].

    aiohttp is imported lazily so the module loads cleanly in environments
    that don't have it (e.g. test runs that mock this function entirely).
    """
    import aiohttp

    if not parsed_requirements:
        return [], []

    timeout = aiohttp.ClientTimeout(total=PYPI_TIMEOUT_SECONDS)
    sem = asyncio.Semaphore(PYPI_CONCURRENCY)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        results = await asyncio.gather(
            *(_fetch_pypi_metadata(session, sem, n, v) for n, v in parsed_requirements)
        )

    records: list[dict] = []
    errors: list[str] = []
    for r in results:
        if not r["success"]:
            errors.append(r["error"] or f"unknown PyPI fetch failure for {r['name']}")
            continue
        license_id = _resolve_license_from_pypi(
            r["license_raw"], r["license_classifiers"]
        )
        record: PackageRecord = {
            "name": r["name"],
            "version": r["version"],
            "license": license_id,
            "license_status": None,
            "cves": [],
            "license_risk": None,
            "security_risk": None,
            "from_cache": False,
            "cached_at": None,
            "transitive": False,  # v1.1: only direct deps resolved
        }
        records.append(record)

    return records, errors


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


def _try_get_l1_cache():
    try:
        from cache.l1_package_cache import l1_cache
        return l1_cache, None
    except Exception as exc:
        return None, f"L1 cache unavailable, continuing without cache: {exc}"


async def sbom_node(state: AgentState) -> dict:
    """
    Resolve direct dependencies declared in the uploaded requirements.txt
    via the PyPI JSON API. Build PackageRecord list, attach L1 cache hits,
    emit sbom_resolved audit event.
    """
    input_type = state.get("input_type", "")
    input_value = state.get("input_value", "")

    errors: list[str] = []

    if input_type != "requirements_file":
        # repo_url was a v1 stub that returned the server's running venv as
        # the scan result — misleading. Removed at the API + input_node
        # validation layers. v1.1 will reintroduce repo_url with real
        # cloning; until then, anything other than requirements_file is a
        # programmer error reaching this branch (state constructed manually
        # with a stale type, etc.).
        return _failure(f"unsupported input_type: {input_type!r}")

    try:
        decoded = base64.b64decode(input_value, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        return _failure(f"input_value is not valid base64 UTF-8: {exc}")

    parsed = parse_requirements_with_versions(decoded)
    if not parsed:
        return _failure(
            "requirements file declared no recognizable direct packages"
        )

    # Strictly-better v1.1 limitation: transitive deps require full
    # dependency resolution (pip-compile / resolvelib). Surface as a
    # non-fatal error so the UI / smoke tests can flag it.
    errors.append(
        "v1.1 limitation: only direct dependencies from requirements.txt "
        "are resolved; transitive dependencies require a future version "
        "with full dependency resolution"
    )

    try:
        records, fetch_errors = await _resolve_packages_from_pypi(parsed)
    except Exception as exc:
        return _failure(f"PyPI resolution failed: {exc}", errors)

    errors.extend(fetch_errors)

    # If EVERY package failed (most likely PyPI unreachable), the scan
    # has nothing to operate on — treat as a fatal SBOM failure.
    if not records:
        return _failure(
            "PyPI API unreachable for all packages; see errors[] for details",
            errors,
        )

    # L1 cache check — same contract as before. Runs AFTER PyPI resolution
    # so the cache populates `from_cache` / `cached_at` / cached license
    # / cached CVEs on the record we already built. LicenseNode + CVENode
    # write to the cache; SBOMNode only reads.
    l1_cache, cache_warning = _try_get_l1_cache()
    if cache_warning:
        errors.append(cache_warning)

    cache_hits = 0
    if l1_cache is not None:
        for record in records:
            cached = l1_cache.get(record["name"], record["version"])
            if not cached:
                continue
            cache_hits += 1
            record["from_cache"] = True
            record["cached_at"] = cached.get("cached_at")
            if cached.get("license") is not None:
                record["license"] = cached["license"]
            if cached.get("cves") is not None:
                record["cves"] = cached["cves"]

    total = len(records)
    direct_count = total              # all PyPI-resolved packages are direct
    transitive_count = 0

    return {
        # No tree shape in PyPI-only resolution; emit the parsed direct
        # list so consumers can still walk a structured representation
        # (api.py's _build_dependency_chains handles an empty/missing tree
        # gracefully and yields [] chains, which the UI treats as
        # "direct dependency").
        "raw_dependency_tree": {
            "tree": [],
            "direct": [{"name": r["name"], "version": r["version"]} for r in records],
        },
        "packages": records,
        "status": "running",
        "audit_events": [
            _sbom_resolved_event(total, direct_count, transitive_count, cache_hits)
        ],
        "errors": errors,
    }
