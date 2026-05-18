"""Tests for nodes.license_node."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_state import CitationSource, DecisionStatus, RiskLevel  # noqa: E402
from nodes import license_node as ln_mod  # noqa: E402
from nodes.license_node import (  # noqa: E402
    build_llm_inference_citation,
    license_node,
)


def _run(coro):
    return asyncio.run(coro)


def _pkg(name: str = "somepkg", version: str = "1.0.0", license_id: str | None = None) -> dict:
    return {
        "name": name,
        "version": version,
        "license": license_id,
        "license_status": None,
        "cves": [],
        "license_risk": None,
        "security_risk": None,
        "from_cache": False,
        "cached_at": None,
        "transitive": False,
    }


_DEFAULT_POLICY = {
    "licenses": {
        "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
        # Post-Design-1 (2026-05-18) per-use_case schema. The "saas"
        # key here matches the use_case=saas default in _state(), so
        # the existing baseline tests continue to exercise the same
        # blocked-licenses set they did before. The other use_cases
        # are covered by the explicit per-use_case matrix tests below.
        "blocked": {
            "saas": ["GPL-3.0-only", "GPL-2.0-only", "AGPL-3.0-only"],
            "internal": [],
            "distributed_binary": [
                "GPL-3.0-only", "GPL-2.0-only", "AGPL-3.0-only",
                "LGPL-3.0-only", "LGPL-2.1-only",
            ],
        },
        "requires_review": ["LGPL-2.1-only", "LGPL-3.0-only", "MPL-2.0"],
        "unknown_license_action": "human_review",
    },
    "policy_hash": "test",
}


def _state(packages: list[dict], use_case: str = "saas", policy: dict | None = None) -> dict:
    return {
        "packages": packages,
        "use_case": use_case,
        "policy": policy or _DEFAULT_POLICY,
    }


def _stub_loaders(monkeypatch) -> None:
    """Replace the on-disk SPDX/curated loaders with in-memory stubs."""
    spdx = {
        "MIT": {"name": "MIT License"},
        "Apache-2.0": {"name": "Apache License 2.0"},
        "BSD-3-Clause": {"name": "BSD 3-Clause License"},
        "GPL-3.0-only": {"name": "GNU General Public License v3.0 only"},
        "GPL-2.0-only": {"name": "GNU General Public License v2.0 only"},
        "LGPL-2.1-only": {"name": "GNU Lesser General Public License v2.1 only"},
        "MPL-2.0": {"name": "Mozilla Public License 2.0"},
    }
    curated = {
        "somepkg": {
            "alternative": "altpkg",
            "version": "1.0",
            "license": "MIT",
            "rationale": "Drop-in replacement, near-identical API",
            "tradeoffs": None,
        }
    }
    monkeypatch.setattr(ln_mod, "_load_spdx_dataset", lambda: (spdx, None))
    monkeypatch.setattr(ln_mod, "_load_curated_mappings", lambda: (curated, None))


# Tests ----------------------------------------------------------------------

def test_mit_in_allowed_list_produces_no_finding(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="requests", version="2.31.0", license_id="MIT")
    result = _run(license_node(_state([pkg])))

    assert result["license_findings"] == []
    event = result["audit_events"][0]
    assert event["event_type"] == "license_scan_complete"
    assert event["payload"]["llm_calls_made"] == 0
    assert event["payload"]["violations_found"] == 0


def test_gpl_blocked_produces_critical_finding_with_curated_swap(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="somepkg", version="1.0.0", license_id="GPL-3.0-only")
    result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    f = result["license_findings"][0]
    assert f["finding_type"] == "license_violation"
    assert f["severity"] == RiskLevel.CRITICAL
    assert f["use_case"] == "saas"

    sources = {c["source"] for c in f["citations"]}
    assert CitationSource.SPDX in sources
    assert CitationSource.POLICY in sources
    assert CitationSource.CURATED_MAPPING in sources

    assert len(f["remediations"]) == 1
    swap = f["remediations"][0]
    assert swap["target_package"] == "altpkg"
    assert swap["confidence"] == "high"


def test_lgpl_invokes_llm_and_creates_finding(monkeypatch):
    _stub_loaders(monkeypatch)
    fake_reasoning = {
        "compatible": "conditional",
        "conditions": "Linking model affects copyleft scope",
        "risk_level": "high",
        "explanation": "LGPL allows dynamic linking but static linking triggers copyleft.",
    }

    pkg = _pkg(name="readline", version="0.1", license_id="LGPL-2.1-only")
    with patch(
        "nodes.license_node._call_llm_for_license_reasoning",
        new=AsyncMock(return_value=fake_reasoning),
    ):
        result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    f = result["license_findings"][0]
    assert f["finding_type"] == "license_restricted"
    assert f["severity"] == RiskLevel.HIGH

    sources = {c["source"] for c in f["citations"]}
    assert CitationSource.SPDX in sources, "SPDX citation must back LLM reasoning"
    assert CitationSource.LLM_INFERENCE in sources, "LLM_INFERENCE citation required"

    event = result["audit_events"][0]
    assert event["payload"]["llm_calls_made"] == 1
    assert event["payload"]["restricted_found"] == 1


def test_missing_license_routes_to_human_review(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="mystery", version="0.1", license_id=None)
    result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    f = result["license_findings"][0]
    assert f["finding_type"] == "license_unknown"
    assert f["decision_status"] == DecisionStatus.HUMAN_REVIEW
    assert len(f["citations"]) >= 1

    sources = {c["source"] for c in f["citations"]}
    assert CitationSource.NONE_FOUND in sources
    assert CitationSource.POLICY in sources


def test_llm_inference_citation_always_has_url_none():
    cit = build_llm_inference_citation("any reasoning text whatsoever")
    assert cit["url"] is None
    assert cit["source"] == CitationSource.LLM_INFERENCE
    assert cit["confidence"] == "inferred"
    assert cit["validated"] is False
    assert cit["validation_method"] == "not_validated"
    assert len(cit["content_hash"]) == 64


def test_every_finding_has_at_least_one_citation(monkeypatch):
    _stub_loaders(monkeypatch)
    fake_reasoning = {
        "compatible": "no",
        "conditions": None,
        "risk_level": "high",
        "explanation": "Incompatible with declared use case.",
    }

    packages = [
        _pkg(name="ok", version="1.0", license_id="MIT"),               # no finding
        _pkg(name="badpkg", version="1.0", license_id="GPL-3.0-only"),  # blocked
        _pkg(name="mystery", version="0.1", license_id=None),           # unknown
        _pkg(name="reviewpkg", version="0.1", license_id="MPL-2.0"),    # LLM
    ]

    with patch(
        "nodes.license_node._call_llm_for_license_reasoning",
        new=AsyncMock(return_value=fake_reasoning),
    ):
        result = _run(license_node(_state(packages)))

    assert len(result["license_findings"]) == 3  # everything but MIT
    for f in result["license_findings"]:
        assert len(f["citations"]) >= 1, f"{f['package']} has empty citations"


def test_llm_says_compatible_yes_produces_no_finding(monkeypatch):
    _stub_loaders(monkeypatch)
    fake = {
        "compatible": "yes",
        "conditions": None,
        "risk_level": "none",
        "explanation": "Permissive license.",
    }
    pkg = _pkg(name="mpl_pkg", version="1.0", license_id="MPL-2.0")
    with patch(
        "nodes.license_node._call_llm_for_license_reasoning",
        new=AsyncMock(return_value=fake),
    ):
        result = _run(license_node(_state([pkg])))

    assert result["license_findings"] == []
    # The LLM was still consulted — counter reflects that.
    assert result["audit_events"][0]["payload"]["llm_calls_made"] == 1


def test_llm_failure_falls_back_to_human_review_finding(monkeypatch):
    _stub_loaders(monkeypatch)

    async def boom(*_args, **_kwargs):
        raise RuntimeError("LLM down")

    pkg = _pkg(name="lgpl_pkg", version="1.0", license_id="LGPL-2.1-only")
    with patch("nodes.license_node._call_llm_for_license_reasoning", side_effect=boom):
        result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    f = result["license_findings"][0]
    assert f["decision_status"] == DecisionStatus.HUMAN_REVIEW
    assert any("LLM reasoning failed" in e for e in result["errors"])
    # Even on LLM failure the finding still has multiple citations.
    sources = {c["source"] for c in f["citations"]}
    assert CitationSource.SPDX in sources
    assert CitationSource.NONE_FOUND in sources


# ---------------------------------------------------------------------------
# Bug A: license_status must be written on every evaluation path
# ---------------------------------------------------------------------------

def _packages_from(result: dict) -> list[dict]:
    """LicenseNode now returns the (mutated) packages list in its dict."""
    pkgs = result.get("packages")
    assert pkgs is not None, "license_node must return packages so LangGraph sees license_status updates"
    return pkgs


def test_fast_path_allowed_sets_license_status_compliant_with_no_finding(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="requests", version="2.31.0", license_id="MIT")
    result = _run(license_node(_state([pkg])))

    assert result["license_findings"] == []
    out_pkg = _packages_from(result)[0]
    assert out_pkg["license_status"] == "compliant"
    # And the original dict was mutated in place (same reference).
    assert pkg["license_status"] == "compliant"


def test_fast_path_blocked_sets_license_status_violation_with_critical_finding(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="somepkg", version="1.0.0", license_id="GPL-3.0-only")
    result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    assert result["license_findings"][0]["severity"] == RiskLevel.CRITICAL
    assert _packages_from(result)[0]["license_status"] == "violation"


def test_missing_license_sets_license_status_unknown_with_medium_finding(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="mystery", version="0.1", license_id=None)
    result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    assert result["license_findings"][0]["finding_type"] == "license_unknown"
    assert _packages_from(result)[0]["license_status"] == "unknown"


def test_spdx_miss_sets_license_status_unknown(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="weird", version="1.0", license_id="My-Custom-License-3.0")
    result = _run(license_node(_state([pkg])))

    assert _packages_from(result)[0]["license_status"] == "unknown"


def test_llm_says_compatible_yes_sets_license_status_compliant(monkeypatch):
    _stub_loaders(monkeypatch)
    fake = {
        "compatible": "yes",
        "conditions": None,
        "risk_level": "none",
        "explanation": "Permissive license.",
    }
    pkg = _pkg(name="mpl_pkg", version="1.0", license_id="MPL-2.0")
    with patch(
        "nodes.license_node._call_llm_for_license_reasoning",
        new=AsyncMock(return_value=fake),
    ):
        result = _run(license_node(_state([pkg])))

    assert result["license_findings"] == []
    assert _packages_from(result)[0]["license_status"] == "compliant"


def test_llm_says_compatible_no_sets_license_status_violation(monkeypatch):
    _stub_loaders(monkeypatch)
    fake = {
        "compatible": "no",
        "conditions": None,
        "risk_level": "high",
        "explanation": "Incompatible with declared use case.",
    }
    pkg = _pkg(name="mpl_pkg", version="1.0", license_id="MPL-2.0")
    with patch(
        "nodes.license_node._call_llm_for_license_reasoning",
        new=AsyncMock(return_value=fake),
    ):
        result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    assert _packages_from(result)[0]["license_status"] == "violation"


def test_llm_says_conditional_sets_license_status_restricted(monkeypatch):
    _stub_loaders(monkeypatch)
    fake = {
        "compatible": "conditional",
        "conditions": "Linking model matters",
        "risk_level": "high",
        "explanation": "LGPL: dynamic vs static linking.",
    }
    pkg = _pkg(name="readline", version="0.1", license_id="LGPL-2.1-only")
    with patch(
        "nodes.license_node._call_llm_for_license_reasoning",
        new=AsyncMock(return_value=fake),
    ):
        result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    assert result["license_findings"][0]["finding_type"] == "license_restricted"
    assert _packages_from(result)[0]["license_status"] == "restricted"


def test_llm_failure_sets_license_status_unknown_defensive_path(monkeypatch):
    _stub_loaders(monkeypatch)

    async def boom(*_a, **_kw):
        raise RuntimeError("LLM down")

    pkg = _pkg(name="lgpl_pkg", version="1.0", license_id="LGPL-2.1-only")
    with patch("nodes.license_node._call_llm_for_license_reasoning", side_effect=boom):
        result = _run(license_node(_state([pkg])))

    assert _packages_from(result)[0]["license_status"] == "unknown"


def test_mixed_packages_each_get_correct_license_status(monkeypatch):
    """Smoke-test the path matrix in a single batch."""
    _stub_loaders(monkeypatch)
    fake = {
        "compatible": "no",
        "conditions": None,
        "risk_level": "high",
        "explanation": "Incompatible.",
    }
    packages = [
        _pkg(name="clean", version="1.0", license_id="MIT"),
        _pkg(name="bad", version="1.0", license_id="GPL-3.0-only"),
        _pkg(name="mystery", version="0.1", license_id=None),
        _pkg(name="review", version="0.1", license_id="MPL-2.0"),
    ]
    with patch(
        "nodes.license_node._call_llm_for_license_reasoning",
        new=AsyncMock(return_value=fake),
    ):
        result = _run(license_node(_state(packages)))

    by_name = {p["name"]: p for p in _packages_from(result)}
    assert by_name["clean"]["license_status"] == "compliant"
    assert by_name["bad"]["license_status"] == "violation"
    assert by_name["mystery"]["license_status"] == "unknown"
    assert by_name["review"]["license_status"] == "violation"  # LLM said "no"


# ---------------------------------------------------------------------------
# Original tests below
# ---------------------------------------------------------------------------


def test_license_not_in_spdx_dataset_treated_as_unknown(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="weird", version="1.0", license_id="My-Custom-License-3.0")
    result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    f = result["license_findings"][0]
    assert f["finding_type"] == "license_unknown"
    assert f["decision_status"] == DecisionStatus.HUMAN_REVIEW


# ---------------------------------------------------------------------------
# Per-use_case blocked lookup (Design 1 — 2026-05-18)
#
# These tests lock the new "blocked is a dict keyed by use_case" schema
# from POLICY.yml. The matrix below mirrors BUGS.md USE_CASE INVESTIGATION
# Task 4 spec. Resolves the P1 use_case bug from the 2026-05-17 smoke test:
# pre-fix, GPL/AGPL/LGPL findings were CRITICAL regardless of use_case.
# ---------------------------------------------------------------------------

def _patch_llm_no(monkeypatch):
    """Patch the license-reasoning LLM to a deterministic 'incompatible'
    verdict. The matrix tests exercise the BLOCKED fast-path only; this
    stub guards against any fall-through that hits the LLM (which would
    require network + API key in a unit test)."""
    async def fake_llm(license_spdx, use_case, spdx_entry):
        return {
            "compatible": "no",
            "conditions": None,
            "risk_level": "high",
            "explanation": "stub: incompatible",
        }
    monkeypatch.setattr(ln_mod, "_call_llm_for_license_reasoning", fake_llm)


def _run_matrix(monkeypatch, license_id: str, use_case: str) -> dict | None:
    """Run license_node for one (license, use_case) cell. Returns the
    single Finding (or None when license_node produced no finding)."""
    _stub_loaders(monkeypatch)
    _patch_llm_no(monkeypatch)
    pkg = _pkg(name="somepkg", version="1.0.0", license_id=license_id)
    result = _run(license_node(_state([pkg], use_case=use_case)))
    findings = result["license_findings"]
    if not findings:
        return None
    assert len(findings) == 1
    return findings[0]


# --- GPL-3.0-only across all three use_cases ---

def test_gpl3_saas_produces_critical_violation(monkeypatch):
    f = _run_matrix(monkeypatch, "GPL-3.0-only", "saas")
    assert f is not None
    assert f["finding_type"] == "license_violation"
    assert f["severity"] == RiskLevel.CRITICAL
    assert f["use_case"] == "saas"


def test_gpl3_internal_produces_no_blocked_violation(monkeypatch):
    """internal use_case has [] blocked — GPL-3.0 falls through past the
    blocked fast-path. Stubbed LLM returns 'no' so we still get a finding
    via the requires_review path (LGPL-3.0-only is on requires_review
    but GPL-3.0-only isn't — it's neither allowed nor blocked for
    internal, so it falls through SPDX → LLM)."""
    f = _run_matrix(monkeypatch, "GPL-3.0-only", "internal")
    # Whatever path it took, it must NOT be the blocked fast-path —
    # severity != CRITICAL (the LLM path on stubbed "no" produces
    # severity HIGH via risk_level="high"), and the citation list
    # must NOT contain the policy.licenses.blocked.* identifier.
    if f is not None:
        assert f["severity"] != RiskLevel.CRITICAL, (
            f"GPL-3.0 under use_case=internal should NOT be CRITICAL "
            f"(the blocked fast-path must not fire). Finding: {f}"
        )
        for c in f["citations"]:
            assert not str(c.get("identifier", "")).startswith(
                "policy.licenses.blocked"
            ), f"blocked-path citation fired for internal use_case: {c}"


def test_gpl3_distributed_binary_produces_critical_violation(monkeypatch):
    f = _run_matrix(monkeypatch, "GPL-3.0-only", "distributed_binary")
    assert f is not None
    assert f["finding_type"] == "license_violation"
    assert f["severity"] == RiskLevel.CRITICAL
    assert f["use_case"] == "distributed_binary"


# --- AGPL-3.0-only across all three use_cases ---

def test_agpl3_saas_produces_critical_violation(monkeypatch):
    f = _run_matrix(monkeypatch, "AGPL-3.0-only", "saas")
    assert f is not None
    assert f["severity"] == RiskLevel.CRITICAL


def test_agpl3_internal_does_not_fire_blocked_path(monkeypatch):
    f = _run_matrix(monkeypatch, "AGPL-3.0-only", "internal")
    if f is not None:
        assert f["severity"] != RiskLevel.CRITICAL
        for c in f["citations"]:
            assert not str(c.get("identifier", "")).startswith(
                "policy.licenses.blocked"
            )


def test_agpl3_distributed_binary_produces_critical_violation(monkeypatch):
    f = _run_matrix(monkeypatch, "AGPL-3.0-only", "distributed_binary")
    assert f is not None
    assert f["severity"] == RiskLevel.CRITICAL


# --- LGPL-3.0-only: requires_review path for saas/internal, blocked for distributed ---

def test_lgpl3_distributed_binary_produces_critical_violation(monkeypatch):
    """LGPL only joins the blocked list for distributed_binary — the
    binary linking model can be incompatible with LGPL's relinkability
    requirement."""
    f = _run_matrix(monkeypatch, "LGPL-3.0-only", "distributed_binary")
    assert f is not None
    assert f["finding_type"] == "license_violation"
    assert f["severity"] == RiskLevel.CRITICAL


def test_lgpl3_saas_does_not_fire_blocked_path(monkeypatch):
    """LGPL-3.0 isn't blocked for saas — it's on requires_review, so it
    falls through to the LLM-reasoning path. Stubbed LLM returns 'no' →
    a license_violation finding gets created via the requires_review
    path, NOT the blocked fast-path. Severity comes from the LLM
    (risk_level='high' → HIGH), NOT the hardcoded CRITICAL from blocked."""
    f = _run_matrix(monkeypatch, "LGPL-3.0-only", "saas")
    if f is not None:
        # If the LLM path produced a finding, severity reflects
        # risk_level="high" — not the CRITICAL hardcoded by the
        # blocked path.
        assert f["severity"] != RiskLevel.CRITICAL or "blocked" not in str(
            [c.get("identifier") for c in f["citations"]]
        )


def test_lgpl3_internal_does_not_fire_blocked_path(monkeypatch):
    f = _run_matrix(monkeypatch, "LGPL-3.0-only", "internal")
    if f is not None:
        for c in f["citations"]:
            assert not str(c.get("identifier", "")).startswith(
                "policy.licenses.blocked"
            )


# --- MIT: always allowed, no finding under any use_case ---

def test_mit_produces_no_finding_under_saas(monkeypatch):
    f = _run_matrix(monkeypatch, "MIT", "saas")
    assert f is None


def test_mit_produces_no_finding_under_internal(monkeypatch):
    f = _run_matrix(monkeypatch, "MIT", "internal")
    assert f is None


def test_mit_produces_no_finding_under_distributed_binary(monkeypatch):
    f = _run_matrix(monkeypatch, "MIT", "distributed_binary")
    assert f is None


# --- Citation identifier includes use_case path for audit traceability ---

def test_blocked_citation_identifier_includes_use_case(monkeypatch):
    """The policy citation on a blocked finding must name the
    per-use_case path so auditors can trace the exact rule. This is the
    audit-traceability contract documented in the BUGS.md design 1 fix."""
    f = _run_matrix(monkeypatch, "GPL-3.0-only", "saas")
    assert f is not None
    policy_cit = next(
        c for c in f["citations"]
        if c["source"] == CitationSource.POLICY
    )
    assert policy_cit["identifier"] == (
        "policy.licenses.blocked.saas[GPL-3.0-only]"
    )
    assert "use_case='saas'" in policy_cit["excerpt"]


def test_blocked_citation_identifier_distinguishes_use_cases(monkeypatch):
    """Same license, different use_cases → different citation identifiers."""
    saas_f = _run_matrix(monkeypatch, "GPL-3.0-only", "saas")
    db_f = _run_matrix(monkeypatch, "GPL-3.0-only", "distributed_binary")
    saas_id = next(
        c["identifier"] for c in saas_f["citations"]
        if c["source"] == CitationSource.POLICY
    )
    db_id = next(
        c["identifier"] for c in db_f["citations"]
        if c["source"] == CitationSource.POLICY
    )
    assert "saas" in saas_id and "distributed_binary" in db_id
    assert saas_id != db_id


# --- Backward compat: legacy flat-list policies still work ---

def test_legacy_flat_blocked_list_still_applies_universally(monkeypatch):
    """For callers that haven't updated to the per-use_case schema (e.g.
    test fixtures, policy_override that still passes a flat list), the
    flat shape is honored as a universal block — same behavior as
    pre-Design-1. Documents the backward-compat path in
    _blocked_for_use_case."""
    _stub_loaders(monkeypatch)
    _patch_llm_no(monkeypatch)
    legacy_policy = {
        "licenses": {
            "allowed": ["MIT"],
            "blocked": ["GPL-3.0-only"],  # flat list, NOT a dict
            "requires_review": [],
            "unknown_license_action": "human_review",
        },
        "policy_hash": "legacy",
    }
    pkg = _pkg(name="x", version="1", license_id="GPL-3.0-only")
    for uc in ("saas", "internal", "distributed_binary"):
        result = _run(license_node(_state([pkg], use_case=uc, policy=legacy_policy)))
        f = result["license_findings"][0]
        assert f["severity"] == RiskLevel.CRITICAL, (
            f"legacy flat blocked list should fire under all use_cases; "
            f"failed for use_case={uc}"
        )
