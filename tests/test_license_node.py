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
        "blocked": ["GPL-3.0-only", "GPL-2.0-only", "AGPL-3.0-only"],
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


def test_license_not_in_spdx_dataset_treated_as_unknown(monkeypatch):
    _stub_loaders(monkeypatch)
    pkg = _pkg(name="weird", version="1.0", license_id="My-Custom-License-3.0")
    result = _run(license_node(_state([pkg])))

    assert len(result["license_findings"]) == 1
    f = result["license_findings"][0]
    assert f["finding_type"] == "license_unknown"
    assert f["decision_status"] == DecisionStatus.HUMAN_REVIEW
