"""Tests for nodes.cve_node."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_state import CitationSource, DecisionStatus, RiskLevel  # noqa: E402
from nodes.cve_node import (  # noqa: E402
    build_none_found_citation,
    build_osv_citation,
    cve_node,
    cvss_to_risk_level,
    extract_cvss_score,
)


def _run(coro):
    return asyncio.run(coro)


def _pkg(name: str = "django", version: str = "4.2.3") -> dict:
    return {
        "name": name,
        "version": version,
        "license": None,
        "license_status": None,
        "cves": [],
        "license_risk": None,
        "security_risk": None,
        "from_cache": False,
        "cached_at": None,
        "transitive": False,
    }


def _state(packages=None, policy=None, use_case: str = "saas") -> dict:
    return {
        "packages": packages if packages is not None else [_pkg()],
        "use_case": use_case,
        "policy": policy or {},
    }


VULN_DJANGO = {
    "id": "GHSA-qm57-vhq3-3fwf",
    "summary": "SQL injection via QuerySet methods on MySQL/MariaDB.",
    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "django"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "4.2.14"}],
                }
            ],
        }
    ],
}


def _osv_response_with_django_vuln() -> dict:
    return {"results": [{"vulns": [VULN_DJANGO]}]}


def _osv_empty_response(n: int = 1) -> dict:
    return {"results": [{} for _ in range(n)]}


# Tests ----------------------------------------------------------------------

def test_finding_shape_with_known_vuln():
    with patch("nodes.cve_node._query_osv_batch",
               new=AsyncMock(return_value=_osv_response_with_django_vuln())):
        result = _run(cve_node(_state()))

    assert len(result["cve_findings"]) == 1
    f = result["cve_findings"][0]

    assert f["package"] == "django"
    assert f["version"] == "4.2.3"
    assert f["finding_type"] == "cve"
    assert f["severity"] == RiskLevel.CRITICAL
    assert f["use_case"] == "saas"
    assert f["decision_status"] == DecisionStatus.PENDING
    assert f["finding_id"].startswith("f-")
    assert "GHSA-qm57-vhq3-3fwf" in f["description"]
    assert f["decision_rationale"] is None
    assert f["decided_at"] is None
    assert f["decided_by"] is None
    assert f["prior_decision"] is None

    assert len(f["citations"]) == 1
    cit = f["citations"][0]
    assert cit["source"] == CitationSource.OSV
    assert cit["identifier"] == "GHSA-qm57-vhq3-3fwf"
    assert cit["url"] == "https://osv.dev/vulnerability/GHSA-qm57-vhq3-3fwf"
    assert cit["validated"] is True
    assert cit["validation_method"] == "api_response"
    assert cit["confidence"] == "authoritative"
    assert len(cit["content_hash"]) == 64

    assert len(f["remediations"]) == 1
    rem = f["remediations"][0]
    assert rem["target_version"] == "4.2.14"
    assert rem["citations"] == [cit]


def test_empty_osv_response_creates_no_findings():
    with patch("nodes.cve_node._query_osv_batch",
               new=AsyncMock(return_value=_osv_empty_response(1))):
        result = _run(cve_node(_state()))

    assert result["cve_findings"] == []
    event = result["audit_events"][0]
    assert event["event_type"] == "cve_scan_complete"
    assert event["payload"]["packages_scanned"] == 1
    assert event["payload"]["packages_with_cves"] == 0
    assert event["payload"]["vulnerabilities_found"] == 0
    assert event["payload"]["findings_created"] == 0


def test_findings_always_have_non_empty_citations():
    # Real CVE findings carry OSV citations.
    with patch("nodes.cve_node._query_osv_batch",
               new=AsyncMock(return_value=_osv_response_with_django_vuln())):
        result = _run(cve_node(_state()))

    for finding in result["cve_findings"]:
        assert len(finding["citations"]) >= 1, "Finding citations must never be empty"
        for cit in finding["citations"]:
            assert "content_hash" in cit and len(cit["content_hash"]) == 64

    # The NONE_FOUND helper builds a complete, hashable citation that any
    # caller can attach when they have no authoritative evidence.
    none_cit = build_none_found_citation("OSV returned no records")
    assert none_cit["source"] == CitationSource.NONE_FOUND
    assert none_cit["url"] is None
    assert none_cit["confidence"] == "none"
    assert none_cit["validated"] is False
    assert none_cit["validation_method"] == "none_found"
    assert len(none_cit["content_hash"]) == 64


def test_cvss_boundary_mapping():
    # Boundary cases that motivated the test: 8.9 vs 9.0 must split HIGH/CRITICAL.
    assert cvss_to_risk_level(9.0) == RiskLevel.CRITICAL
    assert cvss_to_risk_level(8.9) == RiskLevel.HIGH
    assert cvss_to_risk_level(7.0) == RiskLevel.HIGH
    assert cvss_to_risk_level(6.9) == RiskLevel.MEDIUM
    assert cvss_to_risk_level(4.0) == RiskLevel.MEDIUM
    assert cvss_to_risk_level(3.9) == RiskLevel.LOW
    assert cvss_to_risk_level(0.0) == RiskLevel.LOW
    # None score → MEDIUM (over-route to human review rather than silently low)
    assert cvss_to_risk_level(None) == RiskLevel.MEDIUM


def test_cvss_mapping_overridable_via_policy():
    policy_mapping = {
        "critical_threshold": 8.0,
        "high_threshold": 5.0,
        "medium_threshold": 2.0,
    }
    assert cvss_to_risk_level(8.0, policy_mapping) == RiskLevel.CRITICAL
    assert cvss_to_risk_level(5.0, policy_mapping) == RiskLevel.HIGH
    assert cvss_to_risk_level(2.0, policy_mapping) == RiskLevel.MEDIUM
    assert cvss_to_risk_level(1.9, policy_mapping) == RiskLevel.LOW


def test_extract_cvss_score_prefers_v3_then_database_specific():
    # Numeric string in CVSS_V3 entry
    assert extract_cvss_score(
        {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    ) == 7.5

    # CVSS vector string falls through to database_specific.cvss.score
    assert extract_cvss_score({
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
        "database_specific": {"cvss": {"score": 9.1}},
    }) == 9.1

    # No score at all → None
    assert extract_cvss_score({}) is None


def test_batch_order_preservation():
    pkgs = [
        _pkg("django", "4.2.3"),
        _pkg("requests", "2.28.0"),
        _pkg("flask", "2.0.0"),
    ]

    requests_vuln = {
        "id": "GHSA-requests-test",
        "summary": "Test vuln in requests.",
        "severity": [{"type": "CVSS_V3", "score": "5.0"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.31.0"}]}],
            }
        ],
    }

    response = {
        "results": [
            {"vulns": [VULN_DJANGO]},   # index 0 → django
            {"vulns": [requests_vuln]}, # index 1 → requests
            {},                         # index 2 → flask (clean)
        ]
    }

    with patch("nodes.cve_node._query_osv_batch", new=AsyncMock(return_value=response)):
        result = _run(cve_node(_state(packages=pkgs)))

    findings_by_pkg = {f["package"]: f for f in result["cve_findings"]}
    assert set(findings_by_pkg.keys()) == {"django", "requests"}
    assert "flask" not in findings_by_pkg

    assert findings_by_pkg["django"]["citations"][0]["identifier"] == "GHSA-qm57-vhq3-3fwf"
    assert findings_by_pkg["requests"]["citations"][0]["identifier"] == "GHSA-requests-test"
    assert findings_by_pkg["django"]["severity"] == RiskLevel.CRITICAL
    assert findings_by_pkg["requests"]["severity"] == RiskLevel.MEDIUM


def test_osv_failure_logs_error_and_continues():
    async def boom(_packages):
        raise RuntimeError("network down")

    with patch("nodes.cve_node._query_osv_batch", side_effect=boom):
        result = _run(cve_node(_state()))

    assert result["cve_findings"] == []
    assert any("OSV batch query failed" in err for err in result["errors"])
    # Audit event still emitted so AuditNode sees we tried.
    assert result["audit_events"][0]["event_type"] == "cve_scan_complete"


def test_osv_citation_url_comes_from_response_not_llm():
    cit = build_osv_citation(VULN_DJANGO, "2026-05-13T14:32:08Z")
    # URL is constructed verbatim from vuln.id — never invented.
    assert cit["url"] == f"https://osv.dev/vulnerability/{VULN_DJANGO['id']}"
    assert cit["identifier"] == VULN_DJANGO["id"]
    # Excerpt is bounded for UI display
    assert len(cit["excerpt"]) <= 100


def test_build_osv_citation_uses_provided_retrieved_at():
    cit = build_osv_citation(VULN_DJANGO, "2026-05-13T14:32:08Z")
    assert cit["retrieved_at"] == "2026-05-13T14:32:08Z"
