"""
nodes/report_node.py
====================
Final report generation. Runs after AuditNode.

Builds the structured report dict served by GET /scan/results/{job_id}
and stores it in a module-level dict keyed by job_id. v1: in-memory.
v2: replace _reports with a PostgreSQL-backed store.

Decision counts deliberately keep auto / L2-replay / human ACCEPTED
findings in separate buckets — the audit-trail story for each is
different (policy auto vs prior-decision replay vs fresh human review)
and lumping them loses the signal an auditor cares about.

CYA design rule: every report echoes use_case at the top level so the
declared context can never be silently lost between scan initiation
and result retrieval.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from agent_state import AgentState
from audit.verify_chain import verify_chain


# Module-level store. v1: in-memory; v2: PostgreSQL.
_reports: dict[str, dict] = {}


def _severity_value(level) -> str:
    if level is None:
        return "none"
    return getattr(level, "value", str(level)).lower()


def _decision_value(status) -> str:
    if status is None:
        return ""
    return getattr(status, "value", str(status)).lower()


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for f in findings:
        sev_str = _severity_value(f.get("severity"))
        if sev_str in counts:
            counts[sev_str] += 1
    return counts


def _count_by_type(findings: list) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        ft = f.get("finding_type", "unknown")
        counts[ft] = counts.get(ft, 0) + 1
    return counts


def _count_by_decision(findings: list) -> dict:
    """
    Distinguish auto / L2-replay / human accepts in three separate
    buckets so the audit story stays legible (see module docstring).
    """
    counts = {
        "pending_human_review": 0,
        "auto_remediated": 0,
        "auto_accepted": 0,        # decided_by="auto" (policy-driven)
        "l2_replay_accepted": 0,   # decided_by="auto_l2" (memory replay)
        "human_accepted": 0,       # decided_by is a human identifier
        "human_deferred": 0,
    }
    for f in findings:
        status_str = _decision_value(f.get("decision_status"))
        decided_by = f.get("decided_by")

        if status_str == "human_review":
            counts["pending_human_review"] += 1
        elif status_str == "auto_remediate":
            counts["auto_remediated"] += 1
        elif status_str == "accepted":
            if decided_by == "auto":
                counts["auto_accepted"] += 1
            elif decided_by == "auto_l2":
                counts["l2_replay_accepted"] += 1
            else:
                counts["human_accepted"] += 1
        elif status_str == "deferred":
            counts["human_deferred"] += 1

    return counts


def _scanned_at_from_audit(audit_trail: list[dict]) -> Optional[str]:
    """
    Pull the scan_started timestamp from the sealed audit trail. Falls
    back to the first entry's timestamp if scan_started isn't present
    (e.g. a fatal early failure that short-circuited InputNode).
    """
    for entry in audit_trail:
        if entry.get("event_type") == "scan_started":
            return entry.get("timestamp")
    if audit_trail:
        return audit_trail[0].get("timestamp")
    return None


async def report_node(state: AgentState) -> dict:
    job_id = state.get("job_id") or "unknown"
    audit_trail = list(state.get("audit_trail") or [])
    verification = verify_chain(audit_trail)

    license_findings = list(state.get("license_findings") or [])
    cve_findings = list(state.get("cve_findings") or [])
    all_findings = license_findings + cve_findings
    packages = list(state.get("packages") or [])

    summary = {
        "packages_total": len(packages),
        "packages_direct": sum(1 for p in packages if not p.get("transitive")),
        "packages_transitive": sum(1 for p in packages if p.get("transitive")),
        "cache_hits": sum(1 for p in packages if p.get("from_cache")),
        "findings_total": len(all_findings),
        "findings_by_severity": _count_by_severity(all_findings),
        "findings_by_type": _count_by_type(all_findings),
        "decisions": _count_by_decision(all_findings),
    }

    report = {
        "job_id": job_id,
        "use_case": state.get("use_case"),  # always echoed (CYA)
        "scanned_at": _scanned_at_from_audit(audit_trail),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "executive_summary": state.get("risk_summary"),
        "packages": packages,
        "license_findings": license_findings,
        "cve_findings": cve_findings,
        "audit_trail_entry_count": len(audit_trail),
        "chain_valid": verification["chain_valid"],
    }

    _reports[job_id] = report

    return {"errors": []}


def get_report(job_id: str) -> Optional[dict]:
    """Public accessor used by api.py to fetch a stored report."""
    return _reports.get(job_id)


def clear_reports() -> None:
    """Reset the module-level store. Used by tests."""
    _reports.clear()
