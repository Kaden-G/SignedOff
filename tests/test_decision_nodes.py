"""Tests for nodes.decision_gate_node, auto_remediate_node, auto_accept_node."""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_state import DecisionStatus, RiskLevel  # noqa: E402
from cache.l2_decision_memory import l2_memory  # noqa: E402
from nodes.auto_accept_node import auto_accept_node  # noqa: E402
from nodes.auto_remediate_node import auto_remediate_node  # noqa: E402
from nodes.decision_gate_node import decision_gate_node  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _finding(
    severity: RiskLevel = RiskLevel.HIGH,
    finding_type: str = "cve",
    decision_status=DecisionStatus.HUMAN_REVIEW,
    decided_by=None,
    decided_at=None,
    package: str = "django",
    version: str = "4.2.3",
    finding_id: str | None = None,
) -> dict:
    return {
        "finding_id": finding_id or f"f-{uuid.uuid4()}",
        "package": package,
        "version": version,
        "finding_type": finding_type,
        "severity": severity,
        "use_case": "saas",
        "description": "test",
        "recommendation": "fix it",
        "remediations": [],
        "citations": [{"source": "osv", "url": "https://x", "identifier": "x",
                       "excerpt": "x", "retrieved_at": "x", "confidence": "x",
                       "validated": True, "validation_method": "x",
                       "content_hash": "x"}],
        "decision_status": decision_status,
        "decision_rationale": None,
        "decided_at": decided_at,
        "decided_by": decided_by,
        "prior_decision": None,
    }


def _state(**overrides) -> dict:
    base = {
        "job_id": "job-test",
        "use_case": "saas",
        "policy": {"policy_hash": "test-hash"},
        "pending_human_review": [],
        "resolved_findings": [],
    }
    base.update(overrides)
    return base


def setup_function(_):
    l2_memory.clear()


# ---------------------------------------------------------------------------
# DecisionGateNode
# ---------------------------------------------------------------------------

def test_accepted_decision_with_rationale_resolves_finding_and_writes_l2():
    f = _finding(finding_id="f-decide-1", package="django", version="4.2.3",
                 finding_type="cve")
    decisions = [{
        "finding_id": "f-decide-1",
        "decision_status": "accepted",
        "rationale": "Vulnerable code path not exercised in our codebase.",
        "decided_by": "kaden@org.com",
    }]

    with patch("nodes.decision_gate_node.interrupt", return_value=decisions):
        result = _run(decision_gate_node(_state(pending_human_review=[f])))

    assert len(result["resolved_findings"]) == 1
    decided = result["resolved_findings"][0]
    assert decided["decision_status"] == "accepted"
    assert decided["decision_rationale"].startswith("Vulnerable code path")
    assert decided["decided_by"] == "kaden@org.com"
    assert decided["decided_at"] is not None

    assert result["pending_human_review"] == []

    # L2 memory got written
    prior = l2_memory.get(
        "django", "4.2.3", "cve", "saas", "test-hash"
    )
    assert prior is not None
    assert prior["decision_status"] == "accepted"
    assert prior["decided_by"] == "kaden@org.com"

    # Audit event correct
    audit = result["audit_events"][0]
    assert audit["event_type"] == "human_decisions_recorded"
    assert audit["payload"]["decisions"][0]["finding_id"] == "f-decide-1"
    # rationale must NOT be in audit payload
    assert "rationale" not in audit["payload"]["decisions"][0]


def test_accepted_decision_without_rationale_stays_pending_no_l2_write():
    f = _finding(finding_id="f-no-rat", package="lib", version="1.0",
                 finding_type="cve")
    decisions = [{
        "finding_id": "f-no-rat",
        "decision_status": "accepted",
        "rationale": "",  # empty — invalid
        "decided_by": "alice@org.com",
    }]

    with patch("nodes.decision_gate_node.interrupt", return_value=decisions):
        result = _run(decision_gate_node(_state(pending_human_review=[f])))

    assert result["resolved_findings"] == []
    assert len(result["pending_human_review"]) == 1
    assert result["pending_human_review"][0]["finding_id"] == "f-no-rat"
    assert any("Rationale required" in e for e in result["errors"])

    # L2 not written
    assert l2_memory.get("lib", "1.0", "cve", "saas", "test-hash") is None


def test_stale_finding_id_logs_error_does_not_crash():
    f = _finding(finding_id="f-real")
    decisions = [{
        "finding_id": "f-ghost",
        "decision_status": "accepted",
        "rationale": "looks fine",
        "decided_by": "bob@org.com",
    }]

    with patch("nodes.decision_gate_node.interrupt", return_value=decisions):
        result = _run(decision_gate_node(_state(pending_human_review=[f])))

    assert result["resolved_findings"] == []
    assert len(result["pending_human_review"]) == 1  # untouched
    assert any("Stale decision" in e for e in result["errors"])


def test_multiple_decisions_in_one_batch_all_processed():
    findings = [
        _finding(finding_id="f-1", package="a", version="1.0"),
        _finding(finding_id="f-2", package="b", version="2.0"),
        _finding(finding_id="f-3", package="c", version="3.0"),
    ]
    decisions = [
        {"finding_id": "f-1", "decision_status": "accepted",
         "rationale": "ok", "decided_by": "u@org.com"},
        {"finding_id": "f-2", "decision_status": "deferred",
         "rationale": "later", "decided_by": "u@org.com"},
        {"finding_id": "f-3", "decision_status": "auto_remediate",
         "rationale": None, "decided_by": "u@org.com"},
    ]

    with patch("nodes.decision_gate_node.interrupt", return_value=decisions):
        result = _run(decision_gate_node(_state(pending_human_review=findings)))

    assert len(result["resolved_findings"]) == 3
    assert result["pending_human_review"] == []

    audit = result["audit_events"][0]
    audit_ids = {d["finding_id"] for d in audit["payload"]["decisions"]}
    assert audit_ids == {"f-1", "f-2", "f-3"}


def test_auto_remediate_decision_does_not_write_l2():
    f = _finding(finding_id="f-ar", package="x", version="1.0",
                 finding_type="cve")
    decisions = [{
        "finding_id": "f-ar",
        "decision_status": "auto_remediate",
        "rationale": None,  # not required for auto_remediate
        "decided_by": "u@org.com",
    }]

    with patch("nodes.decision_gate_node.interrupt", return_value=decisions):
        result = _run(decision_gate_node(_state(pending_human_review=[f])))

    assert len(result["resolved_findings"]) == 1
    assert result["resolved_findings"][0]["decision_status"] == "auto_remediate"

    # L2 NOT written for auto_remediate
    assert l2_memory.get("x", "1.0", "cve", "saas", "test-hash") is None


# ---------------------------------------------------------------------------
# AutoRemediateNode
# ---------------------------------------------------------------------------

def test_auto_remediate_emits_event_with_correct_finding_ids():
    findings = [
        _finding(finding_id="f-ar-1", decision_status=DecisionStatus.AUTO_REMEDIATE,
                 decided_by="auto", decided_at="2026-05-15T10:00:00Z"),
        _finding(finding_id="f-ar-2", decision_status=DecisionStatus.AUTO_REMEDIATE,
                 decided_by="auto", decided_at="2026-05-15T10:00:00Z",
                 package="other", version="1.0"),
        _finding(finding_id="f-ac-1", decision_status=DecisionStatus.ACCEPTED,
                 decided_by="auto", decided_at="2026-05-15T10:00:00Z"),
    ]
    result = _run(auto_remediate_node(_state(resolved_findings=findings)))

    assert len(result["audit_events"]) == 1
    event = result["audit_events"][0]
    assert event["event_type"] == "auto_remediation_applied"
    assert event["payload"]["count"] == 2
    assert set(event["payload"]["finding_ids"]) == {"f-ar-1", "f-ar-2"}
    assert event["payload"]["remediation_actions"] == []  # v2 placeholder


def test_auto_remediate_no_qualifying_findings_returns_empty_dict():
    findings = [
        _finding(decision_status=DecisionStatus.ACCEPTED, decided_by="auto"),
    ]
    result = _run(auto_remediate_node(_state(resolved_findings=findings)))
    assert result == {}


def test_auto_remediate_does_not_re_stamp_timestamps():
    original_at = "2026-05-15T10:00:00Z"
    f = _finding(
        finding_id="f-ar-stamp",
        decision_status=DecisionStatus.AUTO_REMEDIATE,
        decided_by="auto",
        decided_at=original_at,
    )
    result = _run(auto_remediate_node(_state(resolved_findings=[f])))

    # The finding object passed in must not be mutated.
    assert f["decided_at"] == original_at
    assert f["decided_by"] == "auto"

    # The audit event has its own timestamp (when auto_remediate ran),
    # but the underlying finding's stamp is preserved.
    assert "decided_at" not in result.get("audit_events", [{}])[0]["payload"]


# ---------------------------------------------------------------------------
# AutoAcceptNode
# ---------------------------------------------------------------------------

def test_auto_accept_distinguishes_policy_and_l2_replay():
    findings = [
        _finding(finding_id="f-pol-1", decision_status=DecisionStatus.ACCEPTED,
                 decided_by="auto", decided_at="2026-05-15T10:00:00Z"),
        _finding(finding_id="f-pol-2", decision_status=DecisionStatus.ACCEPTED,
                 decided_by="auto", decided_at="2026-05-15T10:00:00Z",
                 package="b", version="2.0"),
        _finding(finding_id="f-l2-1", decision_status=DecisionStatus.ACCEPTED,
                 decided_by="auto_l2", decided_at="2026-05-15T10:00:00Z",
                 package="c", version="3.0"),
    ]
    result = _run(auto_accept_node(_state(resolved_findings=findings)))

    event = result["audit_events"][0]
    assert event["event_type"] == "auto_accepted"
    assert event["payload"]["total_count"] == 3
    assert event["payload"]["policy_driven_count"] == 2
    assert event["payload"]["l2_replay_count"] == 1
    assert set(event["payload"]["policy_driven_finding_ids"]) == {"f-pol-1", "f-pol-2"}
    assert event["payload"]["l2_replay_finding_ids"] == ["f-l2-1"]


def test_auto_accept_excludes_human_decided_findings():
    findings = [
        _finding(finding_id="f-human", decision_status=DecisionStatus.ACCEPTED,
                 decided_by="kaden@org.com",  # human, not auto
                 decided_at="2026-05-15T10:00:00Z"),
        _finding(finding_id="f-auto", decision_status=DecisionStatus.ACCEPTED,
                 decided_by="auto", decided_at="2026-05-15T10:00:00Z"),
    ]
    result = _run(auto_accept_node(_state(resolved_findings=findings)))

    event = result["audit_events"][0]
    assert event["payload"]["total_count"] == 1
    assert event["payload"]["policy_driven_finding_ids"] == ["f-auto"]
    assert "f-human" not in event["payload"]["policy_driven_finding_ids"]
    assert "f-human" not in event["payload"]["l2_replay_finding_ids"]


def test_auto_accept_no_qualifying_findings_returns_empty_dict():
    findings = [
        _finding(decision_status=DecisionStatus.AUTO_REMEDIATE, decided_by="auto"),
    ]
    result = _run(auto_accept_node(_state(resolved_findings=findings)))
    assert result == {}
