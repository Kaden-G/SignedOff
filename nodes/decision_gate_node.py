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

    # Capture the canonical Finding lists BEFORE the interrupt — the
    # mutations below apply to the same dict objects referenced from
    # these lists, but LangGraph requires the fields to appear in this
    # node's return dict for the mutations to survive checkpoint
    # serialization. (Same pattern as risk_node, fixed in d1c71f8: the
    # in-place mutation works in-process but loses on persistence
    # unless the field is in the return.) Without this, the user-
    # visible /scan/results read from state["cve_findings"] /
    # state["license_findings"] keeps showing decision_status =
    # "human_review" + decided_by = None forever, even though
    # resolved_findings correctly reflects the decision and
    # pending_human_review correctly shrinks.
    license_findings: list[Finding] = list(state.get("license_findings") or [])
    cve_findings: list[Finding] = list(state.get("cve_findings") or [])

    # Pause the pipeline. The API resumes by passing a decisions list
    # via graph.ainvoke(Command(resume=decisions), config).
    decisions = interrupt({"pending_findings": pending})
    decisions = list(decisions or [])

    resolved: list[Finding] = []
    still_pending: list[Finding] = list(pending)
    errors: list[str] = []
    now = _now_iso()

    # LangGraph's checkpointer deserializes state into independent dict
    # objects per field. The `pending` dict for finding f-X is NOT the
    # same Python object as `cve_findings[i]` for the same finding —
    # they're independent copies of the same data. Mutating one does
    # not propagate to the other. So we collect the user-provided
    # updates ONCE and apply them in lockstep to every list that holds
    # a copy of the finding (still_pending, the canonical
    # license_findings / cve_findings lists, and the resolved list).
    def _apply_to_first_match(lst: list[Finding], fid: str, updates: dict) -> bool:
        for f in lst:
            if f.get("finding_id") == fid:
                f.update(updates)
                return True
        return False

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

        updates = {
            "decision_status": decision_status,
            "decision_rationale": decision.get("rationale"),
            "decided_at": now,
            "decided_by": decision.get("decided_by"),
        }
        finding.update(updates)

        # Mirror the update onto the canonical Finding-list copies so
        # the post-checkpoint state agrees across resolved_findings,
        # license_findings, and cve_findings. _apply_to_first_match is
        # tolerant: it's expected to be a no-op on the list that doesn't
        # contain this finding (e.g. a license decision skips the
        # cve_findings list and vice versa).
        _apply_to_first_match(license_findings, finding_id, updates)
        _apply_to_first_match(cve_findings, finding_id, updates)

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
        # license_findings and cve_findings hold the SAME mutated Finding
        # dict references as `resolved`, but unlike resolved_findings (which
        # has operator.add reducer + is in the return), these fields need
        # to be explicitly emitted here so LangGraph's checkpoint replaces
        # state's frozen copy. See top-of-function comment for the
        # canonical bug-pattern reference.
        "license_findings": license_findings,
        "cve_findings": cve_findings,
        "audit_events": [audit_event],
        "errors": errors,
    }
