"""Tests for nodes.risk_node."""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_state import (  # noqa: E402
    CitationSource,
    DecisionStatus,
    RemediationType,
    RiskLevel,
)
from cache.l2_decision_memory import l2_memory  # noqa: E402
from nodes.risk_node import (  # noqa: E402
    DEFAULT_PRIOR_DECISIONS,
    DEFAULT_THRESHOLDS,
    risk_node,
    route_finding,
)


def _run(coro):
    return asyncio.run(coro)


def _citation(source: CitationSource, **overrides) -> dict:
    weak = source in (CitationSource.LLM_INFERENCE, CitationSource.NONE_FOUND)
    base = {
        "source": source,
        "url": None if weak else "https://example.com/x",
        "identifier": None if source == CitationSource.NONE_FOUND else "id-x",
        "excerpt": "x",
        "retrieved_at": "2026-05-15T00:00:00Z",
        "confidence": "none" if source == CitationSource.NONE_FOUND
        else ("inferred" if source == CitationSource.LLM_INFERENCE else "authoritative"),
        "validated": not weak,
        "validation_method": (
            "none_found" if source == CitationSource.NONE_FOUND
            else "not_validated" if source == CitationSource.LLM_INFERENCE
            else "api_response"
        ),
        "content_hash": "h" * 64,
    }
    base.update(overrides)
    return base


def _finding(
    severity: RiskLevel,
    finding_type: str = "cve",
    citations=None,
    package: str = "django",
    version: str = "4.2.3",
) -> dict:
    return {
        "finding_id": f"f-{uuid.uuid4()}",
        "package": package,
        "version": version,
        "finding_type": finding_type,
        "severity": severity,
        "use_case": "saas",
        "description": "test finding",
        "recommendation": "fix it",
        "remediations": [],
        "citations": citations or [_citation(CitationSource.OSV)],
        "decision_status": DecisionStatus.PENDING,
        "decision_rationale": None,
        "decided_at": None,
        "decided_by": None,
        "prior_decision": None,
    }


def _package(name: str = "django", version: str = "4.2.3") -> dict:
    return {
        "name": name,
        "version": version,
        "license": "MIT",
        "license_status": None,
        "cves": [],
        "license_risk": None,
        "security_risk": None,
        "from_cache": False,
        "cached_at": None,
        "transitive": False,
    }


_DEFAULT_POLICY = {
    "thresholds": DEFAULT_THRESHOLDS,
    "prior_decisions": DEFAULT_PRIOR_DECISIONS,
    "policy_hash": "test-hash",
}


def _state(license_findings=None, cve_findings=None, packages=None,
           policy=None, use_case: str = "saas") -> dict:
    return {
        "license_findings": license_findings or [],
        "cve_findings": cve_findings or [],
        "packages": packages or [],
        "use_case": use_case,
        "policy": policy or _DEFAULT_POLICY,
    }


def _patch_summary():
    """Bypass the LLM exec-summary so tests don't reach out to the API."""
    return patch(
        "nodes.risk_node._call_llm_for_summary",
        new=AsyncMock(return_value="stub summary"),
    )


def setup_function(_):
    l2_memory.clear()


# Routing rules --------------------------------------------------------------

def test_critical_authoritative_finding_routes_to_human_review():
    f = _finding(RiskLevel.CRITICAL, finding_type="cve")
    assert route_finding(f, _DEFAULT_POLICY) == DecisionStatus.HUMAN_REVIEW


def test_low_authoritative_license_finding_routes_to_auto_remediate():
    f = _finding(
        RiskLevel.LOW,
        finding_type="license_restricted",
        citations=[_citation(CitationSource.SPDX)],
    )
    assert route_finding(f, _DEFAULT_POLICY) == DecisionStatus.AUTO_REMEDIATE


def test_low_authoritative_cve_finding_routes_to_auto_remediate():
    # security auto_remediate_below=high → LOW + MEDIUM auto_remediate
    f = _finding(RiskLevel.LOW, finding_type="cve")
    assert route_finding(f, _DEFAULT_POLICY) == DecisionStatus.AUTO_REMEDIATE


def test_llm_inference_only_citations_force_human_review_override():
    # Severity LOW would normally auto_remediate. Weak citations override.
    f = _finding(
        RiskLevel.LOW,
        finding_type="license_restricted",
        citations=[_citation(CitationSource.LLM_INFERENCE)],
    )
    assert route_finding(f, _DEFAULT_POLICY) == DecisionStatus.HUMAN_REVIEW


def test_none_found_only_citations_force_human_review_override():
    f = _finding(
        RiskLevel.LOW,
        citations=[_citation(CitationSource.NONE_FOUND)],
    )
    assert route_finding(f, _DEFAULT_POLICY) == DecisionStatus.HUMAN_REVIEW


def test_mixed_strong_and_weak_citations_do_not_trigger_override():
    # SPDX + LLM_INFERENCE together: not a subset of WEAK → falls through
    # to threshold rules.
    f = _finding(
        RiskLevel.LOW,
        finding_type="license_restricted",
        citations=[
            _citation(CitationSource.SPDX),
            _citation(CitationSource.LLM_INFERENCE),
        ],
    )
    assert route_finding(f, _DEFAULT_POLICY) == DecisionStatus.AUTO_REMEDIATE


# L2 memory ------------------------------------------------------------------

def test_l2_auto_accept_with_log_flips_human_review_to_accepted():
    # Custom policy where HIGH severity uses auto_accept_with_log so a
    # finding can both reach HUMAN_REVIEW and then be flipped via L2.
    custom_policy = {
        "thresholds": DEFAULT_THRESHOLDS,
        "prior_decisions": {
            "critical": {"mode": "always_resurface"},
            "high": {"mode": "auto_accept_with_log"},
            "medium": {"mode": "show_for_confirmation"},
            "low": {"mode": "auto_accept_with_log"},
        },
        "policy_hash": "test-hash",
    }

    l2_memory.store(
        package="django", version="4.2.3", finding_type="cve",
        use_case="saas", policy_hash="test-hash",
        decision_status="accepted",
        rationale="Vulnerable code path not exercised in our codebase.",
        decided_by="alice@org.com",
        finding_id="f-original",
        job_id="job-original",
    )

    f = _finding(RiskLevel.HIGH, finding_type="cve")
    with _patch_summary():
        result = _run(risk_node(_state(
            cve_findings=[f],
            packages=[_package()],
            policy=custom_policy,
        )))

    decided = result["risk_matrix"][0]
    assert decided["decision_status"] == DecisionStatus.ACCEPTED
    assert decided["decided_by"] == "auto_l2"
    assert decided["prior_decision"] is not None
    assert decided["prior_decision"]["decided_by"] == "alice@org.com"

    types = [e["event_type"] for e in result["audit_events"]]
    assert "l2_auto_accepted" in types
    assert "risk_matrix_complete" in types

    # Finding flipped → no human-review work left.
    assert result["status"] == "running"
    assert result["pending_human_review"] == []


def test_l2_show_for_confirmation_attaches_prior_but_keeps_human_review():
    l2_memory.store(
        package="django", version="4.2.3", finding_type="cve",
        use_case="saas", policy_hash="test-hash",
        decision_status="accepted",
        rationale="Not exposed.",
        decided_by="bob@org.com",
        finding_id="f-original",
        job_id="job-original",
    )
    # Default policy: HIGH → show_for_confirmation
    f = _finding(RiskLevel.HIGH, finding_type="cve")
    with _patch_summary():
        result = _run(risk_node(_state(cve_findings=[f], packages=[_package()])))

    decided = result["risk_matrix"][0]
    assert decided["decision_status"] == DecisionStatus.HUMAN_REVIEW
    assert decided["prior_decision"] is not None
    assert result["status"] == "awaiting_human"


# Per-package risk dimensions -------------------------------------------------

def test_license_risk_and_security_risk_set_independently():
    pkg = _package("django", "4.2.3")
    license_finding = _finding(
        RiskLevel.HIGH,
        finding_type="license_restricted",
        citations=[_citation(CitationSource.SPDX)],
    )
    cve_finding = _finding(RiskLevel.CRITICAL, finding_type="cve")

    with _patch_summary():
        result = _run(risk_node(_state(
            license_findings=[license_finding],
            cve_findings=[cve_finding],
            packages=[pkg],
        )))

    updated = result["packages"][0]
    assert updated["license_risk"] == RiskLevel.HIGH
    assert updated["security_risk"] == RiskLevel.CRITICAL
    # Two dimensions remain separate — never collapsed to a single number.
    assert updated["license_risk"] != updated["security_risk"]


def test_clean_package_gets_none_risk_dimensions():
    pkg = _package("clean", "1.0")
    with _patch_summary():
        result = _run(risk_node(_state(packages=[pkg])))

    updated = result["packages"][0]
    assert updated["license_risk"] == RiskLevel.NONE
    assert updated["security_risk"] == RiskLevel.NONE


# Sorting + status -----------------------------------------------------------

def test_risk_matrix_sorted_by_severity_descending():
    findings = [
        _finding(RiskLevel.LOW, citations=[_citation(CitationSource.OSV)]),
        _finding(RiskLevel.CRITICAL, citations=[_citation(CitationSource.OSV)]),
        _finding(RiskLevel.HIGH, citations=[_citation(CitationSource.OSV)]),
    ]
    with _patch_summary():
        result = _run(risk_node(_state(cve_findings=findings)))

    severities = [f["severity"] for f in result["risk_matrix"]]
    assert severities == [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.LOW]


def test_status_awaiting_human_when_pending_review_present():
    f = _finding(RiskLevel.CRITICAL)
    with _patch_summary():
        result = _run(risk_node(_state(cve_findings=[f])))
    assert result["status"] == "awaiting_human"
    assert len(result["pending_human_review"]) == 1


def test_status_running_when_everything_auto_resolved():
    f = _finding(RiskLevel.LOW, finding_type="cve")  # → auto_remediate
    with _patch_summary():
        result = _run(risk_node(_state(cve_findings=[f])))
    assert result["status"] == "running"
    assert result["pending_human_review"] == []
    assert len(result["resolved_findings"]) == 1


# Summary fallback -----------------------------------------------------------

def test_llm_summary_failure_falls_back_to_template():
    f = _finding(RiskLevel.HIGH)

    async def boom(*_a, **_kw):
        raise RuntimeError("LLM down")

    with patch("nodes.risk_node._call_llm_for_summary", side_effect=boom):
        result = _run(risk_node(_state(cve_findings=[f])))

    assert result["risk_summary"]
    # Template summary mentions counts directly from summary_data.
    assert "1" in result["risk_summary"]
    assert any("executive summary LLM call failed" in e for e in result["errors"])


def test_audit_event_payload_counts_match_decisions():
    # Two findings that both go to HUMAN_REVIEW (CRITICAL CVEs).
    findings = [
        _finding(RiskLevel.CRITICAL, citations=[_citation(CitationSource.OSV)]),
        _finding(RiskLevel.CRITICAL, citations=[_citation(CitationSource.OSV)],
                 package="other", version="1.0"),
    ]
    with _patch_summary():
        result = _run(risk_node(_state(cve_findings=findings)))

    event = next(
        e for e in result["audit_events"] if e["event_type"] == "risk_matrix_complete"
    )
    assert event["payload"]["total_findings"] == 2
    assert event["payload"]["human_review_count"] == 2
    assert event["payload"]["auto_remediate_count"] == 0
    assert event["payload"]["auto_accept_count"] == 0


# ---------------------------------------------------------------------------
# CVE use-case contextualization
# ---------------------------------------------------------------------------

def _ctx_state(findings, use_case="internal"):
    """State for contextualization tests with raw_osv_records populated."""
    osv_records = {
        f["finding_id"]: {
            "id": "GHSA-fake",
            "summary": "Fake vuln summary.",
            "details": "Long markdown details.",
            "affected": [{"package": {"name": f["package"]}}],
            "references": [],
            "database_specific": {"cwe_ids": []},
        }
        for f in findings
    }
    state = _state(cve_findings=findings, use_case=use_case)
    state["raw_osv_records"] = osv_records
    return state


def _ctx_llm_returning(
    severity_str,
    rationale="Contextual rationale. Confidence: high.",
    key_factor="No public input vector",
    recommended_action_type="version_bump",
    contextualized_recommendation=(
        "Upgrade to the patched version. The contextualization confirms "
        "this CVE is directly reachable in the declared use case."
    ),
):
    """Build an AsyncMock for _call_llm_for_cve_context."""
    return AsyncMock(return_value={
        "reachable": "no",
        "contextualized_severity": severity_str,
        "rationale": rationale,
        "key_factor": key_factor,
        "recommended_action_type": recommended_action_type,
        "contextualized_recommendation": contextualized_recommendation,
    })


def test_high_cve_finding_gets_contextualized_low_cve_does_not():
    high_f = _finding(RiskLevel.HIGH, finding_type="cve")
    low_f = _finding(RiskLevel.LOW, finding_type="cve", package="other", version="1.0")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("low"),
    ) as llm_mock:
        _run(risk_node(_ctx_state([high_f, low_f])))

    # Only the HIGH finding should have triggered the LLM call.
    assert llm_mock.call_count == 1
    assert high_f.get("contextualized_severity") == RiskLevel.LOW
    assert low_f.get("contextualized_severity") is None


def test_license_finding_is_never_contextualized():
    lic_f = _finding(
        RiskLevel.CRITICAL,
        finding_type="license_violation",
        citations=[_citation(CitationSource.SPDX)],
    )
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("low"),
    ) as llm_mock:
        _run(risk_node(_ctx_state([lic_f])))
    assert llm_mock.call_count == 0
    assert lic_f.get("contextualized_severity") is None


def test_contextualization_populates_rationale_and_appends_llm_citation():
    f = _finding(RiskLevel.CRITICAL, finding_type="cve")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("medium", rationale="Use case mitigates this. Confidence: high."),
    ):
        _run(risk_node(_ctx_state([f])))

    assert f["contextualized_severity"] == RiskLevel.MEDIUM
    assert "Use case mitigates" in (f["contextualization_rationale"] or "")
    # The LLM_INFERENCE citation should be appended to the original OSV citation.
    sources = [c["source"] for c in f["citations"]]
    assert CitationSource.LLM_INFERENCE in sources
    llm_cit = next(c for c in f["citations"] if c["source"] == CitationSource.LLM_INFERENCE)
    assert llm_cit["confidence"] == "inferred"
    assert llm_cit["validated"] is False
    assert len(llm_cit["content_hash"]) == 64


def test_routing_uses_max_critical_raw_plus_low_ctx_still_human_review():
    """The LLM cannot downgrade a CRITICAL past the human-review gate."""
    f = _finding(RiskLevel.CRITICAL, finding_type="cve")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("low", rationale="Likely unreachable. Confidence: low."),
    ):
        result = _run(risk_node(_ctx_state([f])))

    assert f["contextualized_severity"] == RiskLevel.LOW
    assert f["decision_status"] == DecisionStatus.HUMAN_REVIEW
    assert result["pending_human_review"] == [f]


def test_routing_uses_max_high_raw_plus_critical_ctx_routes_to_human_review():
    f = _finding(RiskLevel.HIGH, finding_type="cve")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("critical"),
    ):
        result = _run(risk_node(_ctx_state([f])))
    assert f["contextualized_severity"] == RiskLevel.CRITICAL
    assert f["decision_status"] == DecisionStatus.HUMAN_REVIEW
    assert len(result["pending_human_review"]) == 1


def test_llm_failure_leaves_finding_unchanged_no_crash():
    f = _finding(RiskLevel.CRITICAL, finding_type="cve")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=AsyncMock(return_value=None),
    ):
        result = _run(risk_node(_ctx_state([f])))

    assert f.get("contextualized_severity") is None
    assert f.get("contextualization_rationale") is None
    assert f["decision_status"] == DecisionStatus.HUMAN_REVIEW
    assert all(c["source"] != CitationSource.LLM_INFERENCE for c in f["citations"])
    summary = next(
        e for e in result["audit_events"]
        if e["event_type"] == "cve_contextualization_complete"
    )
    assert summary["payload"]["llm_call_failures"] >= 1


def test_audit_events_include_cve_contextualized_per_finding():
    f1 = _finding(RiskLevel.HIGH, finding_type="cve", package="a", version="1")
    f2 = _finding(RiskLevel.CRITICAL, finding_type="cve", package="b", version="2")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("medium"),
    ):
        result = _run(risk_node(_ctx_state([f1, f2])))

    ctx_events = [
        e for e in result["audit_events"] if e["event_type"] == "cve_contextualized"
    ]
    assert len(ctx_events) == 2
    summary = next(
        e for e in result["audit_events"]
        if e["event_type"] == "cve_contextualization_complete"
    )
    assert summary["payload"]["findings_evaluated"] == 2
    # Both went from high/critical → medium → downgraded.
    assert summary["payload"]["downgraded_count"] == 2


# ---------------------------------------------------------------------------
# Context-aware remediation: enum + new Remediation appended
# ---------------------------------------------------------------------------

def test_remediation_type_monitor_value_exists_and_is_string():
    """The new MONITOR enum value must inherit from str and serialize as 'monitor'."""
    assert RemediationType.MONITOR.value == "monitor"
    assert isinstance(RemediationType.MONITOR, str)
    # str-enum: comparing to bare strings works for JSON downstream
    assert RemediationType.MONITOR == "monitor"


def _osv_remediation(version: str = "4.2.14") -> dict:
    """Stand-in for the OSV-derived version_bump remediation built by CVENode."""
    return {
        "type": RemediationType.VERSION_BUMP,
        "description": f"Upgrade to {version}",
        "target_package": None,
        "target_version": version,
        "confidence": "high",
        "rationale": "Patched in OSV record.",
        "tradeoffs": None,
        "citations": [_citation(CitationSource.OSV)],
    }


def _find_ctx_remediation(finding: dict) -> dict:
    """Pick the LLM_INFERENCE-cited remediation out of finding['remediations']."""
    return next(
        r for r in finding["remediations"]
        if any(c["source"] == CitationSource.LLM_INFERENCE for c in r.get("citations", []))
    )


def test_ctx_remediation_version_bump_appended_with_own_llm_inference_citation():
    f = _finding(RiskLevel.HIGH, finding_type="cve")
    f["remediations"] = [_osv_remediation()]  # pre-existing OSV remediation

    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning(
            "high",
            recommended_action_type="version_bump",
            contextualized_recommendation=(
                "Upgrade to a patched version. The vector is reachable here."
            ),
        ),
    ):
        _run(risk_node(_ctx_state([f])))

    # Two remediations total: original OSV + new context-aware
    assert len(f["remediations"]) == 2
    ctx_rem = _find_ctx_remediation(f)
    assert ctx_rem["type"] == RemediationType.VERSION_BUMP
    assert ctx_rem["target_package"] is None
    assert ctx_rem["target_version"] is None
    assert ctx_rem["confidence"] == "low"
    # The new remediation's citation list MUST contain its own LLM_INFERENCE
    # citation — separate from the LLM_INFERENCE citation on the Finding.
    assert len(ctx_rem["citations"]) == 1
    cit = ctx_rem["citations"][0]
    assert cit["source"] == CitationSource.LLM_INFERENCE
    assert cit["url"] is None
    assert cit["validated"] is False
    assert len(cit["content_hash"]) == 64


def test_ctx_remediation_accept_as_is_appended():
    f = _finding(RiskLevel.HIGH, finding_type="cve")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning(
            "low",
            recommended_action_type="accept_as_is",
            contextualized_recommendation=(
                "Accept this finding as low risk. The attack vector does not "
                "reach this deployment model."
            ),
        ),
    ):
        _run(risk_node(_ctx_state([f])))

    ctx_rem = _find_ctx_remediation(f)
    assert ctx_rem["type"] == RemediationType.ACCEPT_AS_IS


def test_ctx_remediation_monitor_appended():
    f = _finding(RiskLevel.HIGH, finding_type="cve")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning(
            "medium",
            recommended_action_type="monitor",
            contextualized_recommendation=(
                "Audit your codebase for the conditional code path. "
                "If present, treat as version_bump priority."
            ),
        ),
    ):
        _run(risk_node(_ctx_state([f])))

    ctx_rem = _find_ctx_remediation(f)
    assert ctx_rem["type"] == RemediationType.MONITOR
    # type is a str-enum, so json.dumps would emit "monitor" downstream
    assert ctx_rem["type"].value == "monitor"


def test_ctx_remediation_invalid_action_type_rejects_entire_result():
    """
    Defensive: if the LLM returns an action_type outside the four-value
    vocabulary, _call_llm_for_cve_context returns None and the
    contextualization is skipped entirely — no Remediation appended,
    no contextualized_severity set, llm_call_failures bumped.
    Validation lives in the REAL _call_llm_for_cve_context, so this
    test exercises it by NOT mocking that function — instead it mocks
    the anthropic client's create() to return the bad payload.
    """
    f = _finding(RiskLevel.HIGH, finding_type="cve")
    f["remediations"] = [_osv_remediation()]

    bad_payload = json.dumps({
        "reachable": "yes",
        "contextualized_severity": "high",
        "rationale": "Looks reachable. Confidence: high.",
        "key_factor": "x",
        "recommended_action_type": "fix_it",  # not in the 4-value vocabulary
        "contextualized_recommendation": "Do the thing that fixes everything.",
    })
    fake_response = SimpleNamespace(content=[SimpleNamespace(text=bad_payload)])
    fake_client = SimpleNamespace(
        messages=SimpleNamespace(create=AsyncMock(return_value=fake_response))
    )
    fake_anthropic_module = SimpleNamespace(AsyncAnthropic=lambda: fake_client)

    with _patch_summary(), patch.dict(
        sys.modules, {"anthropic": fake_anthropic_module}
    ):
        result = _run(risk_node(_ctx_state([f])))

    # No new remediation appended — still only the OSV one.
    assert len(f["remediations"]) == 1
    assert f["remediations"][0]["target_version"] == "4.2.14"
    assert f.get("contextualized_severity") is None
    summary = next(
        e for e in result["audit_events"]
        if e["event_type"] == "cve_contextualization_complete"
    )
    assert summary["payload"]["llm_call_failures"] >= 1


def test_ctx_remediation_empty_recommendation_rejects_result():
    """An empty / too-short contextualized_recommendation also rejects."""
    f = _finding(RiskLevel.HIGH, finding_type="cve")

    bad_payload = json.dumps({
        "reachable": "yes",
        "contextualized_severity": "high",
        "rationale": "ok. Confidence: low.",
        "key_factor": "x",
        "recommended_action_type": "version_bump",
        "contextualized_recommendation": "",   # too short
    })
    fake_response = SimpleNamespace(content=[SimpleNamespace(text=bad_payload)])
    fake_client = SimpleNamespace(
        messages=SimpleNamespace(create=AsyncMock(return_value=fake_response))
    )
    fake_anthropic_module = SimpleNamespace(AsyncAnthropic=lambda: fake_client)

    with _patch_summary(), patch.dict(
        sys.modules, {"anthropic": fake_anthropic_module}
    ):
        _run(risk_node(_ctx_state([f])))

    # No contextualization happened — no LLM_INFERENCE citation, no new remediation.
    assert f["remediations"] == []
    assert all(
        c["source"] != CitationSource.LLM_INFERENCE for c in f["citations"]
    )


def test_ctx_remediation_preserves_existing_version_bump():
    """We APPEND a new remediation alongside the OSV one — we don't replace."""
    f = _finding(RiskLevel.HIGH, finding_type="cve")
    osv_rem = _osv_remediation(version="4.2.14")
    f["remediations"] = [osv_rem]

    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("medium", recommended_action_type="monitor"),
    ):
        _run(risk_node(_ctx_state([f])))

    assert len(f["remediations"]) == 2
    # Original OSV remediation is still present, unmodified, at index 0.
    assert f["remediations"][0] is osv_rem
    assert f["remediations"][0]["type"] == RemediationType.VERSION_BUMP
    assert f["remediations"][0]["target_version"] == "4.2.14"
    # Index 1 is the new context-aware one.
    assert f["remediations"][1]["type"] == RemediationType.MONITOR


def test_ctx_audit_summary_includes_action_type_distribution():
    """cve_contextualization_complete now breaks down counts by action type."""
    f1 = _finding(RiskLevel.HIGH, finding_type="cve", package="a", version="1")
    f2 = _finding(RiskLevel.CRITICAL, finding_type="cve", package="b", version="2")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("medium", recommended_action_type="monitor"),
    ):
        result = _run(risk_node(_ctx_state([f1, f2])))

    summary = next(
        e for e in result["audit_events"]
        if e["event_type"] == "cve_contextualization_complete"
    )
    dist = summary["payload"]["action_type_distribution"]
    # All four vocabulary keys must be present (with zeros where unused).
    assert set(dist.keys()) == {
        "version_bump", "accept_as_is", "compensating_control", "monitor"
    }
    assert dist["monitor"] == 2
    assert dist["version_bump"] == 0


def test_ctx_per_finding_audit_event_includes_recommended_action_type():
    f = _finding(RiskLevel.HIGH, finding_type="cve")
    with _patch_summary(), patch(
        "nodes.risk_node._call_llm_for_cve_context",
        new=_ctx_llm_returning("high", recommended_action_type="compensating_control"),
    ):
        result = _run(risk_node(_ctx_state([f])))

    ctx_event = next(
        e for e in result["audit_events"] if e["event_type"] == "cve_contextualized"
    )
    assert ctx_event["payload"]["recommended_action_type"] == "compensating_control"
