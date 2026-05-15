"""
nodes/auto_accept_node.py
=========================
Records the audit-trail entry for findings auto-accepted by RiskNode.

Only fires for findings with decided_by="auto" (policy-driven) or
"auto_l2" (L2 memory replay) — both are non-human auto decisions.
Human-accepted findings come through DecisionGateNode and emit their
own human_decisions_recorded event there.

The audit payload distinguishes the two auto sub-types because they
have different audit-trail implications: a policy-driven auto-accept
means "policy said this is below the human-review threshold," while
an L2 replay means "a human already decided this exact finding under
this exact policy and use_case." Auditors care about the difference.

Idempotent: returns {} when there's nothing to do.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agent_state import AgentState, DecisionStatus


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def auto_accept_node(state: AgentState) -> dict:
    to_accept = [
        f for f in (state.get("resolved_findings") or [])
        if (
            f["decision_status"] == DecisionStatus.ACCEPTED
            or f["decision_status"] == "accepted"
        )
        and f.get("decided_by") in ("auto", "auto_l2")
    ]
    if not to_accept:
        return {}

    policy_auto = [f for f in to_accept if f.get("decided_by") == "auto"]
    l2_replay = [f for f in to_accept if f.get("decided_by") == "auto_l2"]

    audit_event = {
        "timestamp": _now_iso(),
        "event_type": "auto_accepted",
        "payload": {
            "total_count": len(to_accept),
            "policy_driven_count": len(policy_auto),
            "l2_replay_count": len(l2_replay),
            "policy_driven_finding_ids": [f["finding_id"] for f in policy_auto],
            "l2_replay_finding_ids": [f["finding_id"] for f in l2_replay],
        },
    }

    return {
        "audit_events": [audit_event],
        "errors": [],
    }
