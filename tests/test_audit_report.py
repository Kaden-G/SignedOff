"""Tests for nodes.audit_node, audit.verify_chain, and nodes.report_node."""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_state import DecisionStatus, RiskLevel  # noqa: E402
from audit.verify_chain import GENESIS_PREV_HASH, verify_chain  # noqa: E402
from nodes.audit_node import audit_node  # noqa: E402
from nodes.report_node import (  # noqa: E402
    clear_reports,
    get_report,
    report_node,
)


def _run(coro):
    return asyncio.run(coro)


def _event(timestamp: str, event_type: str, **payload) -> dict:
    return {"timestamp": timestamp, "event_type": event_type, "payload": payload}


def _finding(severity=RiskLevel.HIGH, finding_type="cve", decision_status=DecisionStatus.HUMAN_REVIEW,
             decided_by=None, package="django", version="4.2.3") -> dict:
    return {
        "finding_id": f"f-{uuid.uuid4()}",
        "package": package,
        "version": version,
        "finding_type": finding_type,
        "severity": severity,
        "use_case": "saas",
        "description": "test",
        "recommendation": "fix",
        "remediations": [],
        "citations": [{"source": "osv", "url": "https://x", "identifier": "x",
                       "excerpt": "x", "retrieved_at": "x", "confidence": "x",
                       "validated": True, "validation_method": "x",
                       "content_hash": "x"}],
        "decision_status": decision_status,
        "decision_rationale": None,
        "decided_at": None,
        "decided_by": decided_by,
        "prior_decision": None,
    }


def setup_function(_):
    clear_reports()


# ---------------------------------------------------------------------------
# AuditNode
# ---------------------------------------------------------------------------

def test_empty_audit_events_produces_just_terminal_entry():
    state = {"job_id": "job-1", "use_case": "saas", "audit_events": []}
    result = _run(audit_node(state))

    chain = result["audit_trail"]
    assert len(chain) == 1
    terminal = chain[0]
    assert terminal["event_type"] == "audit_sealed"
    assert terminal["seq"] == 0
    assert terminal["prev_hash"] == GENESIS_PREV_HASH
    # Even with one entry, verify_chain should pass
    assert verify_chain(chain)["verdict"] == "PASS"
    assert result["status"] == "complete"


def test_parallel_events_with_close_timestamps_get_sorted_and_chained():
    # LicenseNode and CVENode emit events with very close timestamps;
    # the chain must still be deterministic.
    events = [
        _event("2026-05-15T10:00:03Z", "cve_scan_complete", count=3),
        _event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1"),
        _event("2026-05-15T10:00:02Z", "sbom_resolved", packages_total=10),
        _event("2026-05-15T10:00:03Z", "license_scan_complete", count=2),
    ]
    state = {"job_id": "job-1", "use_case": "saas", "audit_events": events}
    result = _run(audit_node(state))

    chain = result["audit_trail"]
    # 4 input + 1 terminal
    assert len(chain) == 5
    seqs = [e["seq"] for e in chain]
    assert seqs == [0, 1, 2, 3, 4]
    types_in_order = [e["event_type"] for e in chain]
    assert types_in_order == [
        "scan_started",
        "sbom_resolved",
        "cve_scan_complete",  # tied timestamp — preserved insertion order
        "license_scan_complete",
        "audit_sealed",
    ]
    assert verify_chain(chain)["verdict"] == "PASS"


def test_genesis_block_has_zero_prev_hash():
    events = [_event("2026-05-15T10:00:00Z", "scan_started", job_id="job-1")]
    state = {"job_id": "job-1", "use_case": "saas", "audit_events": events}
    chain = _run(audit_node(state))["audit_trail"]
    assert chain[0]["seq"] == 0
    assert chain[0]["prev_hash"] == GENESIS_PREV_HASH
    assert chain[0]["prev_hash"] == "0" * 64


def test_each_entry_links_to_the_previous_entry_hash():
    events = [
        _event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1"),
        _event("2026-05-15T10:00:02Z", "sbom_resolved", n=5),
        _event("2026-05-15T10:00:03Z", "cve_scan_complete", n=2),
    ]
    state = {"job_id": "job-1", "use_case": "saas", "audit_events": events}
    chain = _run(audit_node(state))["audit_trail"]

    for i in range(1, len(chain)):
        assert chain[i]["prev_hash"] == chain[i - 1]["entry_hash"], (
            f"Entry {i} prev_hash does not match entry {i - 1} entry_hash"
        )


def test_tampering_with_payload_is_detected_at_that_seq():
    events = [
        _event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1"),
        _event("2026-05-15T10:00:02Z", "sbom_resolved", n=5),
        _event("2026-05-15T10:00:03Z", "cve_scan_complete", n=2),
    ]
    state = {"job_id": "job-1", "use_case": "saas", "audit_events": events}
    chain = _run(audit_node(state))["audit_trail"]

    # Mutate seq=1's payload after the fact
    chain[1]["payload"]["n"] = 999

    verdict = verify_chain(chain)
    assert verdict["verdict"] == "FAIL"
    assert verdict["chain_valid"] is False
    assert verdict["broken_at_seq"] == 1


def test_tampering_with_prev_hash_is_detected_at_that_seq():
    events = [
        _event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1"),
        _event("2026-05-15T10:00:02Z", "sbom_resolved", n=5),
    ]
    state = {"job_id": "job-1", "use_case": "saas", "audit_events": events}
    chain = _run(audit_node(state))["audit_trail"]

    # Tamper with seq=1's prev_hash
    chain[1]["prev_hash"] = "f" * 64

    verdict = verify_chain(chain)
    assert verdict["verdict"] == "FAIL"
    assert verdict["broken_at_seq"] == 1


def test_audit_node_sets_status_complete():
    state = {"job_id": "job-1", "use_case": "saas", "audit_events": []}
    result = _run(audit_node(state))
    assert result["status"] == "complete"
    assert result["audit_events"] == []


# ---------------------------------------------------------------------------
# ReportNode
# ---------------------------------------------------------------------------

def _seal(events: list[dict], job_id: str = "job-1") -> list[dict]:
    """Run audit_node to produce a real sealed chain for ReportNode tests."""
    state = {"job_id": job_id, "use_case": "saas", "audit_events": events}
    return _run(audit_node(state))["audit_trail"]


def _report_state(license_findings=None, cve_findings=None, packages=None,
                  audit_trail=None, job_id="job-1", use_case="saas"):
    return {
        "job_id": job_id,
        "use_case": use_case,
        "policy": {"policy_hash": "test"},
        "license_findings": license_findings or [],
        "cve_findings": cve_findings or [],
        "packages": packages or [],
        "audit_trail": audit_trail or [],
        "risk_summary": "stub summary",
    }


def test_report_includes_use_case_cya_echo():
    chain = _seal([_event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1")])
    _run(report_node(_report_state(audit_trail=chain, use_case="saas")))

    report = get_report("job-1")
    assert report is not None
    assert report["use_case"] == "saas"


def test_report_stored_and_retrievable_by_job_id():
    chain = _seal([_event("2026-05-15T10:00:01Z", "scan_started", job_id="job-X")])
    _run(report_node(_report_state(audit_trail=chain, job_id="job-X")))

    fetched = get_report("job-X")
    assert fetched is not None
    assert fetched["job_id"] == "job-X"
    assert get_report("nonexistent") is None


def test_summary_severity_counts_match_input_findings():
    license_findings = [
        _finding(severity=RiskLevel.CRITICAL, finding_type="license_violation"),
        _finding(severity=RiskLevel.HIGH, finding_type="license_restricted"),
    ]
    cve_findings = [
        _finding(severity=RiskLevel.CRITICAL, finding_type="cve"),
        _finding(severity=RiskLevel.MEDIUM, finding_type="cve"),
        _finding(severity=RiskLevel.LOW, finding_type="cve"),
    ]
    chain = _seal([_event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1")])
    _run(report_node(_report_state(
        license_findings=license_findings,
        cve_findings=cve_findings,
        audit_trail=chain,
    )))

    report = get_report("job-1")
    sev = report["summary"]["findings_by_severity"]
    assert sev["critical"] == 2
    assert sev["high"] == 1
    assert sev["medium"] == 1
    assert sev["low"] == 1
    assert sev["none"] == 0
    assert report["summary"]["findings_total"] == 5


def test_decision_counts_distinguish_auto_and_human_and_l2():
    findings = [
        # Pending HUMAN_REVIEW
        _finding(decision_status=DecisionStatus.HUMAN_REVIEW),
        # Auto remediated
        _finding(decision_status=DecisionStatus.AUTO_REMEDIATE, decided_by="auto"),
        # Auto accepted (policy)
        _finding(decision_status=DecisionStatus.ACCEPTED, decided_by="auto"),
        _finding(decision_status=DecisionStatus.ACCEPTED, decided_by="auto"),
        # Auto accepted (L2 replay)
        _finding(decision_status=DecisionStatus.ACCEPTED, decided_by="auto_l2"),
        # Human accepted
        _finding(decision_status=DecisionStatus.ACCEPTED, decided_by="kaden@org.com"),
        # Human deferred
        _finding(decision_status=DecisionStatus.DEFERRED, decided_by="kaden@org.com"),
    ]
    chain = _seal([_event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1")])
    _run(report_node(_report_state(cve_findings=findings, audit_trail=chain)))

    decisions = get_report("job-1")["summary"]["decisions"]
    assert decisions["pending_human_review"] == 1
    assert decisions["auto_remediated"] == 1
    assert decisions["auto_accepted"] == 2
    assert decisions["l2_replay_accepted"] == 1
    assert decisions["human_accepted"] == 1
    assert decisions["human_deferred"] == 1


def test_chain_valid_in_report_reflects_verify_chain():
    # Valid chain
    chain = _seal([
        _event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1"),
        _event("2026-05-15T10:00:02Z", "sbom_resolved", n=3),
    ])
    _run(report_node(_report_state(audit_trail=chain)))
    assert get_report("job-1")["chain_valid"] is True

    # Tamper the chain, run report again — chain_valid should now be False
    clear_reports()
    chain[1]["payload"]["n"] = 999
    _run(report_node(_report_state(audit_trail=chain)))
    assert get_report("job-1")["chain_valid"] is False


def test_empty_findings_produces_zero_counts_without_crashing():
    chain = _seal([_event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1")])
    _run(report_node(_report_state(audit_trail=chain)))

    report = get_report("job-1")
    assert report["summary"]["findings_total"] == 0
    assert all(v == 0 for v in report["summary"]["findings_by_severity"].values())
    assert all(v == 0 for v in report["summary"]["decisions"].values())
    assert report["summary"]["findings_by_type"] == {}
    assert report["packages"] == []


def test_clear_reports_empties_the_store():
    chain = _seal([_event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1")])
    _run(report_node(_report_state(audit_trail=chain)))
    assert get_report("job-1") is not None

    clear_reports()
    assert get_report("job-1") is None


def test_packages_count_breakdown_and_cache_hits():
    packages = [
        {"name": "a", "version": "1", "transitive": False, "from_cache": False,
         "license": None, "license_status": None, "cves": [], "license_risk": None,
         "security_risk": None, "cached_at": None},
        {"name": "b", "version": "1", "transitive": True, "from_cache": True,
         "license": None, "license_status": None, "cves": [], "license_risk": None,
         "security_risk": None, "cached_at": "x"},
        {"name": "c", "version": "1", "transitive": True, "from_cache": True,
         "license": None, "license_status": None, "cves": [], "license_risk": None,
         "security_risk": None, "cached_at": "x"},
    ]
    chain = _seal([_event("2026-05-15T10:00:01Z", "scan_started", job_id="job-1")])
    _run(report_node(_report_state(packages=packages, audit_trail=chain)))

    summary = get_report("job-1")["summary"]
    assert summary["packages_total"] == 3
    assert summary["packages_direct"] == 1
    assert summary["packages_transitive"] == 2
    assert summary["cache_hits"] == 2


def test_scanned_at_pulled_from_scan_started_audit_entry():
    chain = _seal([
        _event("2026-05-15T10:00:01Z", "validation_failed", reason="x", field="y"),
        _event("2026-05-15T10:00:02Z", "scan_started", job_id="job-1"),
    ])
    _run(report_node(_report_state(audit_trail=chain)))

    # Even though validation_failed is earlier in the chain, scanned_at
    # comes from scan_started.
    assert get_report("job-1")["scanned_at"] == "2026-05-15T10:00:02Z"
