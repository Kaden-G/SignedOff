"""
nodes/cve_node.py
=================
CVE scanning for the SignedOff compliance agent.

Queries the OSV.dev batch endpoint for every package in state["packages"]
in a single round-trip, then produces one Finding per CVE per package.
Runs concurrently with LicenseNode after SBOMNode (see graph.py).

CITATION INTEGRITY:
    All citations come from the OSV API response — never the LLM. Each
    Finding is backed by at least one OSV citation with content_hash for
    tamper detection. Clean packages produce no Finding (their cves list
    stays empty); the NONE_FOUND helper is exported for any caller that
    needs to attach an explicit "no evidence" marker downstream.

ERROR PHILOSOPHY:
    OSV failures degrade gracefully — errors get logged and affected
    packages get treated as having no findings. We never set status=failed
    here. RiskNode is responsible for reasoning about incomplete data.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from agent_state import (
    AgentState,
    Citation,
    CitationSource,
    DecisionStatus,
    Finding,
    PackageRecord,
    Remediation,
    RemediationType,
    RiskLevel,
)


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT_SECONDS = 30

DEFAULT_CVSS_THRESHOLDS = {
    "critical_threshold": 9.0,
    "high_threshold": 7.0,
    "medium_threshold": 4.0,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_citation(data: dict) -> str:
    """
    Compute the content_hash over a Citation's serializable fields.

    Enums must be coerced to their string values before serialization or
    json.dumps will raise. The hash itself is excluded from the input —
    it's the output, not part of the input.
    """
    serializable = {
        k: (v.value if isinstance(v, CitationSource) else v)
        for k, v in data.items()
        if k != "content_hash"
    }
    return hashlib.sha256(
        json.dumps(serializable, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def build_osv_citation(vuln: dict, retrieved_at: str) -> Citation:
    """
    Construct an authoritative OSV citation from a raw OSV vulnerability
    record. The url, identifier, and excerpt all come from the API
    response — the LLM never produces any of these.
    """
    vuln_id = vuln["id"]
    summary = (vuln.get("summary") or vuln.get("details") or "")[:100]
    data: dict[str, Any] = {
        "source": CitationSource.OSV,
        "url": f"https://osv.dev/vulnerability/{vuln_id}",
        "identifier": vuln_id,
        "excerpt": summary,
        "retrieved_at": retrieved_at,
        "confidence": "authoritative",
        "validated": True,
        "validation_method": "api_response",
    }
    data["content_hash"] = _hash_citation(data)
    return data  # type: ignore[return-value]


def build_none_found_citation(reason: str) -> Citation:
    """
    Construct an explicit "no evidence" citation. NEVER use an empty
    citation list — absence of evidence must be a positive signal in the
    audit trail and UI rather than ambiguous missing data.
    """
    data: dict[str, Any] = {
        "source": CitationSource.NONE_FOUND,
        "url": None,
        "identifier": None,
        "excerpt": (reason or "")[:100],
        "retrieved_at": _now_iso(),
        "confidence": "none",
        "validated": False,
        "validation_method": "none_found",
    }
    data["content_hash"] = _hash_citation(data)
    return data  # type: ignore[return-value]


def extract_cvss_score(vuln: dict) -> Optional[float]:
    """
    Pull a numeric CVSS score from an OSV vuln record.

    OSV "severity" is a list of {type, score} entries. We prefer CVSS_V3,
    fall back to CVSS_V2, and try the database_specific.cvss.score field
    when neither carries a numeric value (some advisories store the raw
    CVSS vector string in `score` and the numeric in `database_specific`).

    Returns None if no parseable numeric score is found — callers should
    map None to RiskLevel.MEDIUM via cvss_to_risk_level.
    """
    severity_list = vuln.get("severity") or []
    by_type: dict[str, dict] = {}
    for entry in severity_list:
        if isinstance(entry, dict) and entry.get("type"):
            by_type[entry["type"]] = entry

    for sev_type in ("CVSS_V3", "CVSS_V2"):
        entry = by_type.get(sev_type)
        if entry is None:
            continue
        score = entry.get("score")
        if isinstance(score, (int, float)):
            return float(score)
        if isinstance(score, str):
            try:
                return float(score)
            except ValueError:
                # The string is a CVSS vector, not a number — fall through.
                pass

    db_spec = vuln.get("database_specific") or {}
    cvss_obj = db_spec.get("cvss") or {}
    score = cvss_obj.get("score")
    if isinstance(score, (int, float)):
        return float(score)
    if isinstance(score, str):
        try:
            return float(score)
        except ValueError:
            return None

    return None


def cvss_to_risk_level(score: Optional[float], mapping: Optional[dict] = None) -> RiskLevel:
    """
    Map a numeric CVSS score to a RiskLevel.

    Thresholds default to {critical: 9.0, high: 7.0, medium: 4.0} but can
    be overridden per-org via POLICY.yml.

    A None score collapses to MEDIUM — we'd rather over-route to human
    review than silently treat unscored CVEs as low risk.
    """
    if score is None:
        return RiskLevel.MEDIUM

    thresholds = mapping or DEFAULT_CVSS_THRESHOLDS
    critical = float(thresholds.get("critical_threshold", 9.0))
    high = float(thresholds.get("high_threshold", 7.0))
    medium = float(thresholds.get("medium_threshold", 4.0))

    if score >= critical:
        return RiskLevel.CRITICAL
    if score >= high:
        return RiskLevel.HIGH
    if score >= medium:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _find_fix_version(vuln: dict, pkg: PackageRecord) -> Optional[str]:
    """
    Walk vuln["affected"][*].ranges[*].events[*] for the first "fixed"
    version that targets this package's name. Returns None if no fix is
    listed — caller treats the finding as cve_no_fix.
    """
    pkg_name = pkg["name"].lower()
    affected = vuln.get("affected") or []
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        ent_pkg = entry.get("package") or {}
        if (ent_pkg.get("name") or "").lower() != pkg_name:
            continue
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)
    return None


def _build_version_bump_remediation(
    vuln: dict, pkg: PackageRecord, citations: list[Citation]
) -> Optional[Remediation]:
    fix_version = _find_fix_version(vuln, pkg)
    if not fix_version:
        return None
    rem: dict[str, Any] = {
        "type": RemediationType.VERSION_BUMP,
        "description": f"Upgrade {pkg['name']} from {pkg['version']} to {fix_version}",
        "target_package": None,
        "target_version": fix_version,
        "confidence": "high",
        "rationale": (
            f"Version {fix_version} is the patched release per OSV "
            f"record {vuln.get('id', '?')}."
        ),
        "tradeoffs": None,
        "citations": citations,
    }
    return rem  # type: ignore[return-value]


def _build_cve_finding(
    pkg: PackageRecord,
    vuln: dict,
    citations: list[Citation],
    use_case: str,
    cvss_mapping: Optional[dict],
) -> Finding:
    cvss_score = extract_cvss_score(vuln)
    severity = cvss_to_risk_level(cvss_score, cvss_mapping)

    affected = vuln.get("affected") or [{}]
    has_ranges = bool((affected[0] or {}).get("ranges"))
    finding_type = "cve" if has_ranges else "cve_no_fix"

    remediation = _build_version_bump_remediation(vuln, pkg, citations)
    summary = vuln.get("summary") or vuln.get("details") or "No summary available."
    recommendation = (
        f"Upgrade {pkg['name']} to a patched version."
        if remediation else f"No fix available; consider compensating controls."
    )

    finding: dict[str, Any] = {
        "finding_id": f"f-{uuid.uuid4()}",
        "package": pkg["name"],
        "version": pkg["version"],
        "finding_type": finding_type,
        "severity": severity,
        "use_case": use_case,
        "description": f"{vuln['id']}: {summary}",
        "recommendation": recommendation,
        "remediations": [remediation] if remediation else [],
        "citations": citations,
        "decision_status": DecisionStatus.PENDING,
        "decision_rationale": None,
        "decided_at": None,
        "decided_by": None,
        "prior_decision": None,
    }
    return finding  # type: ignore[return-value]


def _cve_scan_complete_event(
    packages_scanned: int,
    vulnerabilities_found: int,
    findings_created: int,
    packages_with_cves: int,
    osv_query_time_ms: int,
) -> dict:
    return {
        "timestamp": _now_iso(),
        "event_type": "cve_scan_complete",
        "payload": {
            "packages_scanned": packages_scanned,
            "vulnerabilities_found": vulnerabilities_found,
            "findings_created": findings_created,
            "packages_with_cves": packages_with_cves,
            "osv_query_time_ms": osv_query_time_ms,
        },
    }


async def _query_osv_batch(packages: list[PackageRecord]) -> dict:
    """
    POST every package as one batch query to the OSV API.

    OSV returns results in the SAME ORDER as queries — callers rely on
    zip(packages, results) for alignment.

    aiohttp is imported lazily so the module loads in environments that
    haven't installed it (tests mock this function entirely).
    """
    import aiohttp

    payload = {
        "queries": [
            {
                "package": {"name": pkg["name"], "ecosystem": "PyPI"},
                "version": pkg["version"],
            }
            for pkg in packages
        ]
    }

    timeout = aiohttp.ClientTimeout(total=OSV_TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(OSV_BATCH_URL, json=payload) as resp:
            resp.raise_for_status()
            return await resp.json()


def _select_cvss_mapping(policy: dict) -> Optional[dict]:
    """
    POLICY.yml puts the CVSS mapping under `vulnerabilities.cvss_mapping`,
    but the design spec also references `thresholds.vulnerabilities.cvss_mapping`.
    Accept either; the spec path wins if both are populated.
    """
    spec_path = (
        policy.get("thresholds", {})
        .get("vulnerabilities", {})
        .get("cvss_mapping")
    )
    if spec_path:
        return spec_path
    return policy.get("vulnerabilities", {}).get("cvss_mapping")


async def cve_node(state: AgentState) -> dict:
    packages: list[PackageRecord] = list(state.get("packages") or [])
    use_case: str = state.get("use_case", "")
    policy: dict = state.get("policy") or {}
    cvss_mapping = _select_cvss_mapping(policy)

    if not packages:
        return {
            "cve_findings": [],
            "audit_events": [_cve_scan_complete_event(0, 0, 0, 0, 0)],
            "errors": [],
        }

    errors: list[str] = []
    started_at = time.perf_counter()
    retrieved_at_iso = _now_iso()

    try:
        osv_response = await _query_osv_batch(packages)
        results = osv_response.get("results") or []
    except Exception as exc:
        errors.append(f"OSV batch query failed; no CVE findings produced: {exc}")
        results = [{} for _ in packages]

    # OSV must return results in the same order as queries. If counts diverge
    # (network truncation, etc.) we pad/truncate to preserve alignment rather
    # than misattribute vulns to the wrong package.
    if len(results) != len(packages):
        errors.append(
            f"OSV returned {len(results)} results for {len(packages)} packages; "
            "padding to preserve query/result alignment"
        )
        if len(results) < len(packages):
            results = list(results) + [{} for _ in range(len(packages) - len(results))]
        else:
            results = list(results)[: len(packages)]

    findings: list[Finding] = []
    packages_with_cves = 0
    vulns_seen = 0

    for pkg, result in zip(packages, results):
        vulns = (result or {}).get("vulns") or []
        if not vulns:
            continue
        packages_with_cves += 1
        for vuln in vulns:
            vulns_seen += 1
            try:
                citation = build_osv_citation(vuln, retrieved_at_iso)
                finding = _build_cve_finding(
                    pkg, vuln, [citation], use_case, cvss_mapping
                )
                findings.append(finding)
            except Exception as exc:
                errors.append(
                    f"failed to build finding for {pkg['name']}=={pkg['version']} "
                    f"vuln {vuln.get('id', '?')}: {exc}"
                )
                continue

    elapsed_ms = int((time.perf_counter() - started_at) * 1000)

    return {
        "cve_findings": findings,
        "audit_events": [
            _cve_scan_complete_event(
                packages_scanned=len(packages),
                vulnerabilities_found=vulns_seen,
                findings_created=len(findings),
                packages_with_cves=packages_with_cves,
                osv_query_time_ms=elapsed_ms,
            )
        ],
        "errors": errors,
    }
