"""Tests for api.py — FastAPI HTTP layer.

Mocks the graph singleton so HTTP tests never run a real pipeline.
Full graph integration is covered by Day 5 integration tests.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import api  # noqa: E402
from agent_state import DecisionStatus, RiskLevel  # noqa: E402
from nodes.report_node import clear_reports  # noqa: E402


@pytest.fixture
def client():
    """Fresh client + cleared in-memory state per test."""
    api._job_metadata.clear()
    clear_reports()
    with TestClient(app=api.app) as c:
        yield c


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _state_obj(values: dict | None) -> SimpleNamespace:
    """Mimic the LangGraph StateSnapshot.values shape."""
    return SimpleNamespace(values=values or {})


def _patch_graph(values: dict | None = None):
    """Patch graph.ainvoke (no-op) and graph.aget_state (returns values)."""
    return patch.multiple(
        api.graph,
        ainvoke=AsyncMock(return_value={}),
        aget_state=AsyncMock(return_value=_state_obj(values)),
        aupdate_state=AsyncMock(return_value=None),
    )


def _seed_job(job_id: str = "job-test", use_case: str = "saas") -> None:
    api._job_metadata[job_id] = {
        "use_case": use_case,
        "started_at": "2026-05-15T10:00:00Z",
        "status": "running",
    }


# ---------------------------------------------------------------------------
# POST /scan/start
# ---------------------------------------------------------------------------

def test_post_scan_start_valid_input_returns_202_with_use_case_echo(client):
    with _patch_graph():
        resp = client.post("/scan/start", json={
            "input_type": "requirements_file",
            "input_value": _b64("requests==2.31.0\n"),
            "use_case": "saas",
        })

    assert resp.status_code == 202
    body = resp.json()
    assert body["job_id"].startswith("job-")
    assert body["use_case"] == "saas"
    assert body["status"] == "running"
    assert "created_at" in body


def test_post_scan_start_invalid_use_case_returns_422(client):
    resp = client.post("/scan/start", json={
        "input_type": "requirements_file",
        "input_value": _b64("django==4.2.3\n"),
        "use_case": "enterprise",  # not in Literal
    })
    assert resp.status_code == 422


def test_post_scan_start_empty_input_value_returns_422(client):
    resp = client.post("/scan/start", json={
        "input_type": "requirements_file",
        "input_value": "",
        "use_case": "saas",
    })
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /scan/status
# ---------------------------------------------------------------------------

def test_get_status_nonexistent_job_returns_404_with_error_shape(client):
    with _patch_graph():
        resp = client.get("/scan/status/job-nonexistent")
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail["error"] == "job_not_found"
    assert "nonexistent" in detail["message"]


def test_get_status_running_job_echoes_use_case(client):
    _seed_job("job-X", use_case="saas")
    state_values = {
        "use_case": "saas",
        "status": "running",
        "packages": [],
        "license_findings": [],
        "cve_findings": [],
        "errors": [],
        "started_at": "2026-05-15T10:00:00Z",
    }
    with _patch_graph(values=state_values):
        resp = client.get("/scan/status/job-X")
    assert resp.status_code == 200
    body = resp.json()
    assert body["use_case"] == "saas"
    assert body["job_id"] == "job-X"


# ---------------------------------------------------------------------------
# GET /scan/results
# ---------------------------------------------------------------------------

def test_get_results_running_scan_returns_200_with_partial_data(client):
    """
    Mid-scan, the endpoint serves a partial view from live graph state.
    The legacy 409 "scan_in_progress" behavior was a UX bug — the data
    is already in state["packages"]/["license_findings"]/["cve_findings"]
    and the UI can render it while polling for completion.
    """
    _seed_job("job-running")
    state_values = {"status": "running", "packages": [], "use_case": "saas"}
    with _patch_graph(values=state_values):
        resp = client.get("/scan/results/job-running")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_status"] == "running"
    assert body["job_id"] == "job-running"
    assert body["use_case"] == "saas"
    # Partial view: collections present and empty, not missing.
    assert body["packages"] == []
    assert body["license_findings"] == []
    assert body["cve_findings"] == []


def test_get_results_completed_returns_stored_report(client):
    from nodes.report_node import _reports
    _seed_job("job-done", use_case="internal")
    _reports["job-done"] = {
        "job_id": "job-done",
        "use_case": "internal",
        "summary": {"findings_total": 0},
        "packages": [],
        "license_findings": [],
        "cve_findings": [],
        "scanned_at": "2026-05-15T10:00:00Z",
        "completed_at": "2026-05-15T10:00:31Z",
        "executive_summary": "stub",
        "audit_trail_entry_count": 1,
        "chain_valid": True,
    }
    with _patch_graph():
        resp = client.get("/scan/results/job-done")
    assert resp.status_code == 200
    body = resp.json()
    assert body["use_case"] == "internal"
    # Completed reports get scan_status="complete" stamped on response.
    assert body["scan_status"] == "complete"


# ---------------------------------------------------------------------------
# POST /scan/decision
# ---------------------------------------------------------------------------

def test_post_decision_accepted_without_rationale_returns_422(client):
    _seed_job()
    resp = client.post("/scan/decision/f-1", json={
        "job_id": "job-test",
        "decision_status": "accepted",
        "rationale": "",
        "decided_by": "kaden@org.com",
    })
    assert resp.status_code == 422


def test_post_decision_already_decided_returns_409(client):
    _seed_job()
    resolved = [{
        "finding_id": "f-already",
        "decision_status": DecisionStatus.ACCEPTED,
        "package": "django",
        "version": "4.2.3",
    }]
    state_values = {
        "use_case": "saas",
        "pending_human_review": [],
        "resolved_findings": resolved,
    }
    with _patch_graph(values=state_values):
        resp = client.post("/scan/decision/f-already", json={
            "job_id": "job-test",
            "decision_status": "accepted",
            "rationale": "Looks fine to me",
            "decided_by": "kaden@org.com",
        })
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["error"] == "already_decided"
    assert detail["current_status"] == "accepted"


def test_post_decision_valid_resolves_finding_and_returns_state(client):
    _seed_job()
    pending = [{
        "finding_id": "f-pending",
        "decision_status": DecisionStatus.HUMAN_REVIEW,
        "package": "django",
        "version": "4.2.3",
    }]
    state_before = _state_obj({
        "use_case": "saas",
        "pending_human_review": pending,
        "resolved_findings": [],
    })
    state_after = _state_obj({
        "use_case": "saas",
        "pending_human_review": [],  # decision processed
        "resolved_findings": [],
    })

    with patch.object(api.graph, "aget_state",
                      new=AsyncMock(side_effect=[state_before, state_after])), \
         patch("api.resume_after_hitl", new=AsyncMock(return_value=None)):
        resp = client.post("/scan/decision/f-pending", json={
            "job_id": "job-test",
            "decision_status": "accepted",
            "rationale": "Vulnerable code path not exercised.",
            "decided_by": "kaden@org.com",
        })

    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_id"] == "f-pending"
    assert body["use_case"] == "saas"
    assert body["pending_remaining"] == 0
    assert body["graph_status"] == "finalizing"


# ---------------------------------------------------------------------------
# GET /audit/verify
# ---------------------------------------------------------------------------

def test_get_audit_verify_clean_chain_returns_pass(client):
    # Build a real chain via audit_node so verify_chain returns PASS
    import asyncio
    from nodes.audit_node import audit_node
    chain_state = {
        "job_id": "job-audit",
        "use_case": "saas",
        "audit_events": [
            {"timestamp": "2026-05-15T10:00:01Z",
             "event_type": "scan_started",
             "payload": {"job_id": "job-audit"}},
        ],
    }
    audit_trail = asyncio.run(audit_node(chain_state))["audit_trail"]

    _seed_job("job-audit")
    with _patch_graph(values={"use_case": "saas", "audit_trail": audit_trail}):
        resp = client.get("/audit/verify/job-audit")

    assert resp.status_code == 200
    body = resp.json()
    assert body["chain_valid"] is True
    assert body["verdict"] == "PASS"
    assert body["broken_at_seq"] is None
    assert body["entries_verified"] == len(audit_trail)


# ---------------------------------------------------------------------------
# GET /scan/risk-matrix
# ---------------------------------------------------------------------------

def _seed_completed_report(job_id: str = "job-rm", use_case: str = "saas") -> None:
    from nodes.report_node import _reports
    _seed_job(job_id, use_case=use_case)
    _reports[job_id] = {
        "job_id": job_id,
        "use_case": use_case,
        "scanned_at": "2026-05-15T10:00:00Z",
        "completed_at": "2026-05-15T10:00:31Z",
        "summary": {},
        "packages": [
            {"name": "django", "version": "4.2.3", "transitive": False,
             "from_cache": False, "license": "BSD-3-Clause",
             "license_status": "compliant",
             "license_risk": RiskLevel.NONE, "security_risk": RiskLevel.CRITICAL,
             "cves": [], "cached_at": None},
            {"name": "lib", "version": "1.0", "transitive": True,
             "from_cache": False, "license": "MIT",
             "license_status": "compliant",
             "license_risk": RiskLevel.NONE, "security_risk": RiskLevel.NONE,
             "cves": [], "cached_at": None},
        ],
        "cve_findings": [{
            "finding_id": "f-cve-1",
            "package": "django",
            "version": "4.2.3",
            "finding_type": "cve",
            "severity": RiskLevel.CRITICAL,
            "description": "SQL injection",
            "recommendation": "Upgrade Django",
            "decision_status": DecisionStatus.HUMAN_REVIEW,
            "remediations": [{
                "type": "version_bump",
                "target_version": "4.2.14",
                "target_package": None,
                "confidence": "high",
                "rationale": "patched",
                "tradeoffs": None,
                "citations": [],
            }],
            "citations": [{"source": "osv", "url": "https://osv.dev/x",
                           "identifier": "GHSA-x", "excerpt": "x",
                           "retrieved_at": "x", "confidence": "x",
                           "validated": True, "validation_method": "x",
                           "content_hash": "x"}],
        }],
        "license_findings": [],
        "audit_trail_entry_count": 1,
        "chain_valid": True,
        "executive_summary": "stub",
    }


def test_get_risk_matrix_grouped_returns_rows_shape(client):
    _seed_completed_report()
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-rm?view=grouped")
    assert resp.status_code == 200
    body = resp.json()
    assert body["use_case"] == "saas"
    assert "rows" in body
    assert "summary" in body
    rows_by_pkg = {r["package"]: r for r in body["rows"]}
    assert "django" in rows_by_pkg
    assert rows_by_pkg["django"]["security_risk"] == "critical"
    assert rows_by_pkg["django"]["has_fix_available"] is True


def test_get_risk_matrix_flat_returns_findings_shape(client):
    _seed_completed_report()
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-rm?view=flat")
    assert resp.status_code == 200
    body = resp.json()
    assert body["use_case"] == "saas"
    assert "findings" in body
    f = body["findings"][0]
    assert f["finding_id"] == "f-cve-1"
    assert f["severity"] == "critical"
    assert f["fix_version"] == "4.2.14"
    assert f["has_fix_available"] is True
    assert f["primary_citation_source"] == "osv"


# ---------------------------------------------------------------------------
# CORS + use_case echo invariants
# ---------------------------------------------------------------------------

def test_cors_headers_present_on_response(client):
    """OPTIONS preflight should return ACAO."""
    with _patch_graph():
        resp = client.options(
            "/scan/start",
            headers={
                "Origin": "https://lovable.dev",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
    assert resp.status_code in (200, 204)
    assert resp.headers.get("access-control-allow-origin") in ("*", "https://lovable.dev")


def test_use_case_echoed_across_job_context_endpoints(client):
    """use_case must appear in every response carrying job context."""
    _seed_completed_report("job-echo", use_case="distributed_binary")
    state_values = {
        "use_case": "distributed_binary",
        "status": "complete",
        "packages": [],
        "license_findings": [],
        "cve_findings": [],
        "errors": [],
        "started_at": "2026-05-15T10:00:00Z",
        "audit_trail": [],
        "pending_human_review": [],
    }
    with _patch_graph(values=state_values):
        endpoints = [
            "/scan/status/job-echo",
            "/scan/results/job-echo",
            "/scan/risk-matrix/job-echo",
            "/scan/risk-matrix/job-echo?view=flat",
            "/scan/pending-review/job-echo",
            "/audit/trail/job-echo",
        ]
        for ep in endpoints:
            r = client.get(ep)
            assert r.status_code == 200, f"{ep} failed: {r.status_code} {r.text}"
            assert r.json().get("use_case") == "distributed_binary", (
                f"{ep} did not echo use_case: {r.json()}"
            )


# ---------------------------------------------------------------------------
# GET /demo/requirements
# ---------------------------------------------------------------------------

def test_get_demo_requirements_returns_file_content(client):
    resp = client.get("/demo/requirements")
    assert resp.status_code == 200
    body = resp.json()
    assert body["filename"] == "demo_requirements.txt"
    # Sentinel substrings from the real demo file
    assert "django==4.2.3" in body["content"]
    assert "mysqlclient" in body["content"]


# ---------------------------------------------------------------------------
# Dependency chain builder
# ---------------------------------------------------------------------------

def _sample_tree():
    """Pipdeptree-shaped tree: factory-boy → faker → text-unidecode."""
    return [
        {
            "package_name": "factory-boy",
            "installed_version": "3.3.0",
            "dependencies": [
                {
                    "package_name": "faker",
                    "installed_version": "24.0.0",
                    "dependencies": [
                        {
                            "package_name": "text-unidecode",
                            "installed_version": "1.3",
                            "dependencies": [],
                        }
                    ],
                }
            ],
        },
        {
            "package_name": "django",
            "installed_version": "4.2.3",
            "dependencies": [],
        },
    ]


def test_build_dependency_chains_direct_dep_has_empty_chain():
    chains = api._build_dependency_chains({"tree": _sample_tree()})
    assert chains["django"] == []
    assert chains["factory-boy"] == []


def test_build_dependency_chains_transitive_dep_has_parent_chain():
    chains = api._build_dependency_chains({"tree": _sample_tree()})
    assert chains["faker"] == ["factory-boy"]
    assert chains["text-unidecode"] == ["factory-boy", "faker"]


def test_build_dependency_chains_accepts_bare_list_form():
    """Should also accept the bare list (un-wrapped) shape."""
    chains = api._build_dependency_chains(_sample_tree())
    assert chains["faker"] == ["factory-boy"]


def test_build_dependency_chains_handles_empty_and_garbage_input():
    assert api._build_dependency_chains({}) == {}
    assert api._build_dependency_chains(None) == {}
    assert api._build_dependency_chains({"tree": []}) == {}
    # Malformed entries should be ignored, not crash.
    weird = {"tree": [{"no_name_field": True, "dependencies": [None, "bad"]}]}
    assert api._build_dependency_chains(weird) == {}


# ---------------------------------------------------------------------------
# Risk matrix — dependency_chain on rows
# ---------------------------------------------------------------------------

def _seed_completed_report_with_tree(job_id: str = "job-rm-chain"):
    """Like _seed_completed_report but seeds packages whose names match the
    sample tree so we can assert chain placement on grouped rows."""
    from nodes.report_node import _reports
    _seed_job(job_id, use_case="saas")
    _reports[job_id] = {
        "job_id": job_id,
        "use_case": "saas",
        "scanned_at": "2026-05-15T10:00:00Z",
        "completed_at": "2026-05-15T10:00:31Z",
        "summary": {},
        "packages": [
            {"name": "django", "version": "4.2.3", "transitive": False,
             "from_cache": False, "license": "BSD-3-Clause",
             "license_status": "compliant",
             "license_risk": RiskLevel.NONE, "security_risk": RiskLevel.NONE,
             "cves": [], "cached_at": None},
            {"name": "factory-boy", "version": "3.3.0", "transitive": False,
             "from_cache": False, "license": "MIT",
             "license_status": "compliant",
             "license_risk": RiskLevel.NONE, "security_risk": RiskLevel.NONE,
             "cves": [], "cached_at": None},
            {"name": "faker", "version": "24.0.0", "transitive": True,
             "from_cache": False, "license": "MIT",
             "license_status": "compliant",
             "license_risk": RiskLevel.NONE, "security_risk": RiskLevel.NONE,
             "cves": [], "cached_at": None},
            {"name": "text-unidecode", "version": "1.3", "transitive": True,
             "from_cache": False, "license": "Artistic-1.0",
             "license_status": "restricted",
             "license_risk": RiskLevel.MEDIUM, "security_risk": RiskLevel.NONE,
             "cves": [], "cached_at": None},
        ],
        "cve_findings": [],
        "license_findings": [],
        "raw_dependency_tree": {"tree": _sample_tree()},
        "audit_trail_entry_count": 1,
        "chain_valid": True,
        "executive_summary": "stub",
    }


def test_risk_matrix_grouped_includes_dependency_chain_field(client):
    _seed_completed_report_with_tree()
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-rm-chain?view=grouped")
    assert resp.status_code == 200
    rows = {r["package"]: r for r in resp.json()["rows"]}
    for pkg in ("django", "factory-boy", "faker", "text-unidecode"):
        assert "dependency_chain" in rows[pkg], (
            f"dependency_chain missing on row for {pkg}"
        )


def test_risk_matrix_grouped_chain_is_empty_for_direct_deps(client):
    _seed_completed_report_with_tree()
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-rm-chain?view=grouped")
    rows = {r["package"]: r for r in resp.json()["rows"]}
    assert rows["django"]["dependency_chain"] == []
    assert rows["factory-boy"]["dependency_chain"] == []


def test_risk_matrix_grouped_chain_lists_parents_for_transitives(client):
    _seed_completed_report_with_tree()
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-rm-chain?view=grouped")
    rows = {r["package"]: r for r in resp.json()["rows"]}
    assert rows["faker"]["dependency_chain"] == ["factory-boy"]
    assert rows["text-unidecode"]["dependency_chain"] == [
        "factory-boy", "faker"
    ]


def test_risk_matrix_grouped_chain_defaults_to_empty_for_unknown_package(client):
    """A package that exists in the report but not the dep tree gets []."""
    from nodes.report_node import _reports
    _seed_completed_report_with_tree()
    _reports["job-rm-chain"]["packages"].append({
        "name": "orphan", "version": "0.1", "transitive": True,
        "from_cache": False, "license": "MIT", "license_status": "compliant",
        "license_risk": RiskLevel.NONE, "security_risk": RiskLevel.NONE,
        "cves": [], "cached_at": None,
    })
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-rm-chain?view=grouped")
    rows = {r["package"]: r for r in resp.json()["rows"]}
    assert rows["orphan"]["dependency_chain"] == []


# ---------------------------------------------------------------------------
# Risk matrix — dependency_chain on flat view + pending-review
# ---------------------------------------------------------------------------

def _seed_completed_report_with_findings_and_tree(job_id: str = "job-flat-chain"):
    """Seeds a report with CVE findings on packages that have known chain
    positions. Used to assert dependency_chain on flat view rows."""
    from nodes.report_node import _reports
    _seed_job(job_id, use_case="saas")
    _reports[job_id] = {
        "job_id": job_id,
        "use_case": "saas",
        "scanned_at": "2026-05-15T10:00:00Z",
        "completed_at": "2026-05-15T10:00:31Z",
        "summary": {},
        "packages": [
            {"name": "django", "version": "4.2.3", "transitive": False,
             "from_cache": False, "license": "BSD-3-Clause",
             "license_status": "compliant",
             "license_risk": RiskLevel.NONE, "security_risk": RiskLevel.CRITICAL,
             "cves": [], "cached_at": None},
            {"name": "text-unidecode", "version": "1.3", "transitive": True,
             "from_cache": False, "license": "Artistic-1.0",
             "license_status": "restricted",
             "license_risk": RiskLevel.MEDIUM, "security_risk": RiskLevel.NONE,
             "cves": [], "cached_at": None},
        ],
        "cve_findings": [{
            "finding_id": "f-cve-django",
            "package": "django",
            "version": "4.2.3",
            "finding_type": "cve",
            "severity": RiskLevel.CRITICAL,
            "description": "SQL injection",
            "recommendation": "Upgrade",
            "decision_status": DecisionStatus.HUMAN_REVIEW,
            "remediations": [],
            "citations": [{"source": "osv", "url": "https://osv.dev/x",
                           "identifier": "GHSA-x", "excerpt": "x",
                           "retrieved_at": "x", "confidence": "x",
                           "validated": True, "validation_method": "x",
                           "content_hash": "x"}],
        }],
        "license_findings": [{
            "finding_id": "f-lic-textunidecode",
            "package": "text-unidecode",
            "version": "1.3",
            "finding_type": "license_restricted",
            "severity": RiskLevel.MEDIUM,
            "description": "Artistic-1.0 detected",
            "recommendation": "Review",
            "decision_status": DecisionStatus.HUMAN_REVIEW,
            "remediations": [],
            "citations": [{"source": "spdx", "url": "https://spdx.org/Artistic-1.0",
                           "identifier": "Artistic-1.0", "excerpt": "x",
                           "retrieved_at": "x", "confidence": "x",
                           "validated": True, "validation_method": "x",
                           "content_hash": "x"}],
        }],
        "raw_dependency_tree": {"tree": _sample_tree()},
        "audit_trail_entry_count": 1,
        "chain_valid": True,
        "executive_summary": "stub",
    }


def test_risk_matrix_flat_includes_dependency_chain_field(client):
    _seed_completed_report_with_findings_and_tree()
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-flat-chain?view=flat")
    assert resp.status_code == 200
    findings = {f["finding_id"]: f for f in resp.json()["findings"]}
    # Direct dep (django) → empty chain
    assert findings["f-cve-django"]["dependency_chain"] == []
    # Two-level transitive (text-unidecode pulled in by factory-boy → faker)
    assert findings["f-lic-textunidecode"]["dependency_chain"] == [
        "factory-boy", "faker"
    ]


def test_pending_review_includes_dependency_chain_on_each_finding(client):
    _seed_job("job-pending-chain", use_case="saas")
    pending_findings = [
        {
            "finding_id": "f-cve-django",
            "package": "django",
            "version": "4.2.3",
            "finding_type": "cve",
            "severity": RiskLevel.CRITICAL,
            "use_case": "saas",
            "decision_status": DecisionStatus.HUMAN_REVIEW,
            "remediations": [],
            "citations": [],
            "description": "x", "recommendation": "x",
            "prior_decision": None,
        },
        {
            "finding_id": "f-lic-textunidecode",
            "package": "text-unidecode",
            "version": "1.3",
            "finding_type": "license_restricted",
            "severity": RiskLevel.MEDIUM,
            "use_case": "saas",
            "decision_status": DecisionStatus.HUMAN_REVIEW,
            "remediations": [],
            "citations": [],
            "description": "x", "recommendation": "x",
            "prior_decision": None,
        },
    ]
    state_values = {
        "use_case": "saas",
        "pending_human_review": pending_findings,
        "policy": {},
        "raw_dependency_tree": {"tree": _sample_tree()},
    }
    with _patch_graph(values=state_values):
        resp = client.get("/scan/pending-review/job-pending-chain")
    assert resp.status_code == 200
    findings = {f["finding_id"]: f for f in resp.json()["findings"]}
    assert findings["f-cve-django"]["dependency_chain"] == []
    assert findings["f-lic-textunidecode"]["dependency_chain"] == [
        "factory-boy", "faker"
    ]


# ---------------------------------------------------------------------------
# Partial views mid-scan — /scan/risk-matrix and /scan/results
# (regression: previously these returned 404/409 when no completed
# report existed; now they fall back to live graph state)
# ---------------------------------------------------------------------------

def _mid_scan_state_values(use_case: str = "saas") -> dict:
    """Realistic live-state snapshot with one CVE finding already produced."""
    return {
        "use_case": use_case,
        "status": "awaiting_human",
        "started_at": "2026-05-17T10:00:00Z",
        "packages": [
            {"name": "django", "version": "4.2.3", "transitive": False,
             "from_cache": False, "license": "BSD-3-Clause",
             "license_status": "compliant",
             "license_risk": RiskLevel.NONE, "security_risk": RiskLevel.CRITICAL,
             "cves": [], "cached_at": None},
        ],
        "cve_findings": [{
            "finding_id": "f-mid-1",
            "package": "django",
            "version": "4.2.3",
            "finding_type": "cve",
            "severity": RiskLevel.CRITICAL,
            "description": "SQL injection",
            "recommendation": "Upgrade",
            "decision_status": DecisionStatus.HUMAN_REVIEW,
            "remediations": [{
                "type": "version_bump",
                "target_version": "4.2.14",
                "target_package": None,
                "confidence": "high",
                "rationale": "patched",
                "tradeoffs": None,
                "citations": [],
            }],
            "citations": [{"source": "osv", "url": "https://osv.dev/x",
                           "identifier": "GHSA-x", "excerpt": "x",
                           "retrieved_at": "x", "confidence": "x",
                           "validated": True, "validation_method": "x",
                           "content_hash": "x"}],
        }],
        "license_findings": [],
        "raw_dependency_tree": {"tree": []},
        "pending_human_review": [],
        "resolved_findings": [],
    }


def test_risk_matrix_returns_200_with_partial_data_when_running(client):
    _seed_job("job-running-rm", use_case="saas")
    values = _mid_scan_state_values()
    values["status"] = "running"
    with _patch_graph(values=values):
        resp = client.get("/scan/risk-matrix/job-running-rm?view=grouped")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_status"] == "running"
    assert body["use_case"] == "saas"
    # The mid-scan finding shows up in the grouped rows.
    rows_by_pkg = {r["package"]: r for r in body["rows"]}
    assert "django" in rows_by_pkg
    assert rows_by_pkg["django"]["security_risk"] == "critical"


def test_risk_matrix_returns_200_with_partial_data_when_awaiting_human(client):
    _seed_job("job-hitl-rm", use_case="saas")
    with _patch_graph(values=_mid_scan_state_values()):
        resp = client.get("/scan/risk-matrix/job-hitl-rm?view=grouped")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_status"] == "awaiting_human"
    assert any(r["package"] == "django" for r in body["rows"])


def test_risk_matrix_flat_view_also_works_mid_scan(client):
    _seed_job("job-flat-mid", use_case="saas")
    with _patch_graph(values=_mid_scan_state_values()):
        resp = client.get("/scan/risk-matrix/job-flat-mid?view=flat")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_status"] == "awaiting_human"
    assert any(f["finding_id"] == "f-mid-1" for f in body["findings"])


def test_risk_matrix_completed_response_carries_scan_status_complete(client):
    """The complete-report path must also tag the response with scan_status."""
    _seed_completed_report()
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-rm?view=grouped")
    assert resp.status_code == 200
    assert resp.json()["scan_status"] == "complete"


def test_results_returns_200_with_partial_data_when_awaiting_human(client):
    _seed_job("job-hitl-results", use_case="saas")
    with _patch_graph(values=_mid_scan_state_values()):
        resp = client.get("/scan/results/job-hitl-results")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_status"] == "awaiting_human"
    assert body["use_case"] == "saas"
    # The mid-scan finding is in the response.
    assert any(f["finding_id"] == "f-mid-1" for f in body["cve_findings"])
    # Summary echoes what's analyzed so far.
    assert body["summary"]["findings_total"] == 1


def test_risk_matrix_404_only_when_job_genuinely_unknown(client):
    """job_id absent from _job_metadata → 404. job_id present but no
    report and empty state → still 200 partial view (the job exists)."""
    # Genuinely unknown job → 404
    with _patch_graph():
        resp = client.get("/scan/risk-matrix/job-never-existed?view=grouped")
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "job_not_found"

    # Job exists in metadata but graph hasn't produced state yet → 200
    # with empty partial view.
    _seed_job("job-empty", use_case="saas")
    with _patch_graph(values={}):
        resp = client.get("/scan/risk-matrix/job-empty?view=grouped")
    assert resp.status_code == 200
    body = resp.json()
    # Falls back to metadata for status + use_case.
    assert body["use_case"] == "saas"
    assert body["scan_status"] in ("running", "awaiting_human")
    assert body["rows"] == []


def test_results_404_only_when_job_genuinely_unknown(client):
    with _patch_graph():
        resp = client.get("/scan/results/job-never-existed")
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "job_not_found"


# ---------------------------------------------------------------------------
# Static dashboard mount
# ---------------------------------------------------------------------------

def test_root_serves_static_dashboard_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    body = resp.text
    # Sanity-check the dashboard markup is present
    assert "SignedOff" in body
    assert "Compliance officer for Python supply chains" in body
