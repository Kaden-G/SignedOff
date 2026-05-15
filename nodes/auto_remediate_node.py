"""
nodes/auto_remediate_node.py
============================
Records the audit-trail entry for findings RiskNode marked
AUTO_REMEDIATE.

This node is intentionally narrow: RiskNode already stamped decided_by
and decided_at on these findings, so re-stamping here would be
redundant work and would clutter the audit trail with duplicate
events. v1 of this node only emits a single audit event recording that
auto-remediation was "applied." v2 will actually open GitHub PRs and
list their URLs in remediation_actions.

Idempotent: returns {} when there's nothing to do.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agent_state import AgentState, DecisionStatus


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def auto_remediate_node(state: AgentState) -> dict:
    to_remediate = [
        f for f in (state.get("resolved_findings") or [])
        if f["decision_status"] == DecisionStatus.AUTO_REMEDIATE
        or f["decision_status"] == "auto_remediate"
    ]
    if not to_remediate:
        return {}

    audit_event = {
        "timestamp": _now_iso(),
        "event_type": "auto_remediation_applied",
        "payload": {
            "count": len(to_remediate),
            "finding_ids": [f["finding_id"] for f in to_remediate],
            "packages": [
                {
                    "name": f["package"],
                    "version": f["version"],
                    "finding_type": f["finding_type"],
                }
                for f in to_remediate
            ],
            # v2: populate with opened PR URLs
            "remediation_actions": [],
        },
    }

    return {
        "audit_events": [audit_event],
        "errors": [],
    }
