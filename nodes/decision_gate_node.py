"""
nodes/decision_gate_node.py
===========================
Human-in-the-loop gate for findings RiskNode routed to HUMAN_REVIEW.

Pauses the LangGraph pipeline via langgraph.types.interrupt() until the
API layer (POST /scan/decision/{finding_id}) resumes execution by
injecting a list of human decisions through graph.aupdate_state().

INVARIANTS:
  - rationale is REQUIRED for accepted/deferred decisions; missing
    rationale leaves the finding pending and logs an error.
  - Stale finding_ids (already decided or never pending) are logged
    and skipped — never crash, never silently overwrite.
  - Only accepted/deferred decisions get written to L2 memory. Auto
    decisions are policy-driven and re-derived next scan, so memoizing
    them adds noise without value.
  - decided_at and decided_by are stamped fresh by THIS node — RiskNode
    leaves them None for HUMAN_REVIEW findings.

State writes:
  - resolved_findings: Annotated[list, operator.add] — appended via
    LangGraph reducer.
  - pending_human_review: REPLACED with the remaining-pending list (no
    reducer on this field by design).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from agent_state import AgentState, Finding


try:
    from langgraph.types import interrupt
except ImportError:  # langgraph isn't installed in this env (e.g. unit tests)
    def interrupt(payload):
        raise RuntimeError(
            "langgraph not installed; interrupt() requires the LangGraph runtime"
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_by_id(findings: list[Finding], finding_id: str) -> Optional[Finding]:
    return next((f for f in findings if f["finding_id"] == finding_id), None)


def _try_get_l2_memory():
    try:
        from cache.l2_decision_memory import l2_memory
        return l2_memory, None
    except Exception as exc:
        return None, f"L2 decision memory unavailable: {exc}"


async def decision_gate_node(state: AgentState) -> dict:
    pending: list[Finding] = list(state.get("pending_human_review") or [])
    if not pending:
        return {}

    # Pause the pipeline. The API resumes by passing a decisions list as
    # the interrupt's return value via graph.aupdate_state(...).
    decisions = interrupt({"pending_findings": pending})
    decisions = list(decisions or [])

    resolved: list[Finding] = []
    still_pending: list[Finding] = list(pending)
    errors: list[str] = []
    now = _now_iso()

    for decision in decisions:
        finding_id = decision.get("finding_id")
        decision_status = decision.get("decision_status")

        if decision_status in ("accepted", "deferred"):
            if not decision.get("rationale"):
                errors.append(
                    f"Rationale required for accepted/deferred decisions. "
                    f"finding_id: {finding_id}"
                )
                continue

        finding = find_by_id(still_pending, finding_id)
        if not finding:
            errors.append(
                f"Stale decision: finding_id {finding_id!r} not found in pending"
            )
            continue

        finding["decision_status"] = decision_status
        finding["decision_rationale"] = decision.get("rationale")
        finding["decided_at"] = now
        finding["decided_by"] = decision.get("decided_by")

        resolved.append(finding)
        still_pending = [
            f for f in still_pending if f["finding_id"] != finding_id
        ]

    # L2 memory — only accepted/deferred decisions are worth memoizing.
    # Auto decisions will be re-derived by RiskNode on the next scan.
    l2_memory, l2_warn = _try_get_l2_memory()
    if l2_warn:
        errors.append(l2_warn)

    if l2_memory is not None:
        policy_hash = (state.get("policy") or {}).get("policy_hash") or "unknown"
        use_case = state.get("use_case") or "unknown"
        job_id = state.get("job_id") or "unknown"
        for f in resolved:
            if f["decision_status"] not in ("accepted", "deferred"):
                continue
            try:
                l2_memory.store(
                    package=f["package"],
                    version=f["version"],
                    finding_type=f["finding_type"],
                    use_case=use_case,
                    policy_hash=policy_hash,
                    decision_status=f["decision_status"],
                    rationale=f["decision_rationale"],
                    decided_by=f["decided_by"],
                    finding_id=f["finding_id"],
                    job_id=job_id,
                )
            except Exception as exc:
                errors.append(f"L2 store failed for {f['finding_id']}: {exc}")

    audit_event = {
        "timestamp": now,
        "event_type": "human_decisions_recorded",
        "payload": {
            "decisions": [
                {
                    "finding_id": f["finding_id"],
                    "package": f["package"],
                    "version": f["version"],
                    "decision_status": f["decision_status"],
                    "decided_by": f["decided_by"],
                    # rationale intentionally NOT in audit payload — full
                    # text lives on the finding; the audit entry only
                    # records THAT a decision occurred.
                }
                for f in resolved
            ],
            "errors_count": len(errors),
        },
    }

    return {
        "resolved_findings": resolved,
        "pending_human_review": still_pending,
        "audit_events": [audit_event],
        "errors": errors,
    }
