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

import asyncio
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
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
OSV_TIMEOUT_SECONDS = 30
OSV_ENRICH_CONCURRENCY = 10

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


def extract_vuln_summary(vuln: dict, max_len: int = 200) -> str:
    """
    Pull a human-readable summary out of an OSV record.

    Priority:
      1. vuln["summary"]           — short headline, usually one line
      2. vuln["details"]           — long markdown body; strip formatting
                                     and take the first paragraph
      3. explicit fallback string  — surfaces the missing data instead of
                                     pretending nothing was wrong
    """
    summary = (vuln.get("summary") or "").strip()
    if summary:
        return summary[:max_len]

    details = (vuln.get("details") or "").strip()
    if details:
        cleaned = details.replace("#", "").replace("*", "")
        # Pick the first substantive paragraph. OSV details usually open
        # with a Markdown header like "### Summary" which, once "#" is
        # stripped, collapses to a single word — useless as a description.
        # Skip any paragraph shorter than ~20 chars (treat as header).
        for para in cleaned.split("\n\n"):
            collapsed = " ".join(para.split()).strip()
            if len(collapsed) >= 20:
                return collapsed[:max_len]
        # Fallback: nothing substantive found — return whatever we have.
        flat = " ".join(cleaned.split()).strip()
        if flat:
            return flat[:max_len]

    return f"No summary or details available in OSV record for {vuln.get('id', 'unknown')}."


def build_osv_citation(vuln: dict, retrieved_at: str) -> Citation:
    """
    Construct an authoritative OSV citation from a raw OSV vulnerability
    record. The url, identifier, and excerpt all come from the API
    response — the LLM never produces any of these.
    """
    vuln_id = vuln["id"]
    excerpt = extract_vuln_summary(vuln, max_len=100)
    data: dict[str, Any] = {
        "source": CitationSource.OSV,
        "url": f"https://osv.dev/vulnerability/{vuln_id}",
        "identifier": vuln_id,
        "excerpt": excerpt,
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


def _parse_cvss_vector(vector: str) -> Optional[float]:
    """
    Compute the base score from a CVSS v3.x or v4.0 vector string.

    Prefers the `cvss` library (pip install cvss) for accuracy across the
    whole metric matrix. Falls back to a minimal v3.x base-score
    implementation if the library isn't installed — enough to keep
    smoke tests honest in stripped-down environments. Returns None on
    any parse failure rather than guessing.
    """
    if not isinstance(vector, str):
        return None
    try:
        try:
            from cvss import CVSS3, CVSS4
            if vector.startswith("CVSS:3"):
                return float(CVSS3(vector).base_score)
            if vector.startswith("CVSS:4"):
                return float(CVSS4(vector).base_score)
        except ImportError:
            pass

        # Manual fallback — CVSS v3.x only. Spec at
        # https://www.first.org/cvss/v3.1/specification-document
        if not vector.startswith("CVSS:3"):
            return None

        metrics: dict[str, str] = {}
        for part in vector.split("/")[1:]:
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k] = v

        AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", ""), 0)
        AC = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", ""), 0)
        scope = metrics.get("S", "U")
        PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
        PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
        PR = (PR_C if scope == "C" else PR_U).get(metrics.get("PR", ""), 0)
        UI = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", ""), 0)
        C_ = {"H": 0.56, "L": 0.22, "N": 0}.get(metrics.get("C", ""), 0)
        I_ = {"H": 0.56, "L": 0.22, "N": 0}.get(metrics.get("I", ""), 0)
        A_ = {"H": 0.56, "L": 0.22, "N": 0}.get(metrics.get("A", ""), 0)

        iss = 1 - ((1 - C_) * (1 - I_) * (1 - A_))
        if scope == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * AV * AC * PR * UI

        if impact <= 0:
            return 0.0

        raw = (impact + exploitability) if scope == "U" else 1.08 * (impact + exploitability)
        base = min(raw, 10)

        import math
        return math.ceil(base * 10) / 10
    except Exception:
        return None


def extract_cvss_score(vuln: dict) -> Optional[float]:
    """
    Numeric CVSS score from an OSV vuln record, in priority order:

      1. affected[].database_specific.cvss.score
         Many GHSA-backed records put a clean numeric here. Easiest win.

      2. severity[].score
         OSV's documented field. In practice the value is a CVSS VECTOR
         STRING ("CVSS:3.1/AV:N/AC:H/..."), not a number — parse it.
         Some older records do put a numeric string; we try float() too.

      3. database_specific.severity
         String label ("CRITICAL" / "HIGH" / "MODERATE" / "LOW") on the
         vuln itself. Last-resort anchor when nothing parseable exists.

    Returns None if none of the above produce a usable value. Callers map
    None → RiskLevel.MEDIUM via cvss_to_risk_level (over-routes to human
    review rather than silently treating unscored CVEs as low).
    """
    # Priority 1: numeric score in affected[].database_specific.cvss
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        cvss = ((affected.get("database_specific") or {}).get("cvss")) or {}
        score = cvss.get("score")
        if isinstance(score, (int, float)) and 0.0 <= score <= 10.0:
            return float(score)
        if isinstance(score, str):
            try:
                parsed = float(score)
                if 0.0 <= parsed <= 10.0:
                    return parsed
            except ValueError:
                pass

    # Priority 2: severity[].score — usually a CVSS vector string
    for sev_entry in vuln.get("severity") or []:
        if not isinstance(sev_entry, dict):
            continue
        score_str = sev_entry.get("score")
        if isinstance(score_str, str) and score_str.startswith("CVSS:"):
            parsed = _parse_cvss_vector(score_str)
            if parsed is not None:
                return parsed
        if isinstance(score_str, (int, float)):
            return float(score_str)
        if isinstance(score_str, str):
            try:
                return float(score_str)
            except ValueError:
                pass

    # Priority 3: string severity label → numeric anchor
    db_spec = vuln.get("database_specific") or {}
    sev_label = (db_spec.get("severity") or "").upper()
    label_to_score = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MODERATE": 5.5,
        "MEDIUM": 5.5,
        "LOW": 3.0,
    }
    if sev_label in label_to_score:
        return label_to_score[sev_label]

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
    summary = extract_vuln_summary(vuln, max_len=200)
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
        # Populated by RiskNode for HIGH/CRITICAL CVE findings only.
        # See Finding TypedDict docs in agent_state.py.
        "contextualized_severity": None,
        "contextualization_rationale": None,
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

    NOTE: the batch endpoint returns only `{id: ...}` stubs per vuln,
    NOT the full record. Callers must follow up with _enrich_vulns to
    fetch severity / summary / affected data.

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


async def _enrich_vulns(vuln_ids: set[str]) -> dict[str, dict]:
    """
    Fetch the full record for each vuln_id via /v1/vulns/{id}.

    The batch endpoint returns only IDs. severity[], summary, details,
    and affected[].database_specific.cvss all live on the per-vuln
    record. Without this enrichment, extract_cvss_score() returns None
    for every vuln and the priority chain has nothing to work with.

    Concurrent fetches are capped at OSV_ENRICH_CONCURRENCY to avoid
    hammering OSV. A failed individual fetch yields {"id": vid} so the
    caller can still attach SOMETHING and the rest of the batch
    proceeds — a single 404 must not break the whole scan.

    Tests typically mock this function entirely.
    """
    if not vuln_ids:
        return {}

    import aiohttp

    timeout = aiohttp.ClientTimeout(total=OSV_TIMEOUT_SECONDS)
    sem = asyncio.Semaphore(OSV_ENRICH_CONCURRENCY)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async def fetch_one(vid: str) -> tuple[str, Optional[dict]]:
            url = OSV_VULN_URL.format(vuln_id=vid)
            async with sem:
                try:
                    async with session.get(url) as resp:
                        resp.raise_for_status()
                        return vid, await resp.json()
                except Exception:
                    return vid, None

        pairs = await asyncio.gather(*(fetch_one(v) for v in vuln_ids))

    # Only return successful fetches. Callers fall back to the stub for
    # any id not in this dict, which is also the right behavior when
    # tests provide already-enriched stubs and skip the network entirely.
    return {vid: data for vid, data in pairs if data is not None}


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
            "raw_osv_records": {},
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

    # Collect unique vuln IDs from the batch stubs and fetch full records.
    # The batch endpoint only returns {"id": ...} per vuln — severity,
    # summary, and affected[] all live on /v1/vulns/{id}. Without this
    # enrichment, every finding would collapse to MEDIUM with a
    # placeholder description.
    #
    # Skip enrichment for stubs that ALREADY carry substance (tests inject
    # full vuln dicts directly into the batch response; we don't want to
    # round-trip to OSV for those).
    _STUB_SUBSTANCE_KEYS = ("severity", "affected", "summary", "details")
    unique_ids: set[str] = set()
    for result in results:
        for v in (result or {}).get("vulns") or []:
            if isinstance(v, dict) and v.get("id"):
                if not any(v.get(k) for k in _STUB_SUBSTANCE_KEYS):
                    unique_ids.add(v["id"])

    try:
        vuln_details = await _enrich_vulns(unique_ids)
    except Exception as exc:
        errors.append(
            f"OSV per-vuln enrichment failed; severity will fall back to "
            f"the label/None defaults: {exc}"
        )
        vuln_details = {}

    findings: list[Finding] = []
    raw_osv_records: dict[str, dict] = {}
    packages_with_cves = 0
    vulns_seen = 0

    for pkg, result in zip(packages, results):
        vulns = (result or {}).get("vulns") or []
        if not vulns:
            continue
        packages_with_cves += 1
        for vuln_stub in vulns:
            vulns_seen += 1
            vuln_id = vuln_stub.get("id") if isinstance(vuln_stub, dict) else None
            # Prefer the enriched record; fall back to the stub if the
            # per-vuln fetch failed or this id wasn't in the batch.
            vuln = vuln_details.get(vuln_id) if vuln_id else None
            if not vuln:
                vuln = vuln_stub
            try:
                citation = build_osv_citation(vuln, retrieved_at_iso)
                finding = _build_cve_finding(
                    pkg, vuln, [citation], use_case, cvss_mapping
                )
                findings.append(finding)
                # Stash the raw OSV record so RiskNode can ground its
                # use-case contextualization LLM prompts on real data
                # rather than asking the LLM to recall from training.
                raw_osv_records[finding["finding_id"]] = vuln
            except Exception as exc:
                errors.append(
                    f"failed to build finding for {pkg['name']}=={pkg['version']} "
                    f"vuln {vuln.get('id', '?')}: {exc}"
                )
                continue

    elapsed_ms = int((time.perf_counter() - started_at) * 1000)

    return {
        "cve_findings": findings,
        "raw_osv_records": raw_osv_records,
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
