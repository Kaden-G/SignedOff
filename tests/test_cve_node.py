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
    _parse_cvss_vector,
    build_none_found_citation,
    build_osv_citation,
    cve_node,
    cvss_to_risk_level,
    extract_cvss_score,
    extract_vuln_summary,
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


def test_extract_cvss_score_priority_chain():
    # Priority 2: numeric string in severity[].score is parsed as a number.
    assert extract_cvss_score(
        {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    ) == 7.5

    # Priority 2: complete CVSS vector string is parsed to its base score.
    score = extract_cvss_score({
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    })
    assert score is not None and 9.7 <= score <= 9.9  # canonical 9.8

    # Priority 1: numeric in affected[].database_specific.cvss.score wins
    # over a CVSS vector in severity[].
    assert extract_cvss_score({
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"database_specific": {"cvss": {"score": 4.4}}}],
    }) == 4.4

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


# ---------------------------------------------------------------------------
# Real-shape OSV fixtures (taken from actual osv.dev responses)
# ---------------------------------------------------------------------------

# Shape observed for urllib3 1.26.x (GHSA-2xpw-w6gg-jr37, real osv.dev record).
# Score lives BOTH in severity[].score as a CVSS vector AND in
# affected[].database_specific.cvss.score as a number.
OSV_URLLIB3_REAL_SHAPE = {
    "id": "GHSA-2xpw-w6gg-jr37",
    "summary": "urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects",
    "details": (
        "### Impact\n\nurllib3 doesn't treat the `Proxy-Authorization` header as one that "
        "should be stripped...\n\n### Affected versions\n\n- urllib3 < 1.26.19"
    ),
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    ],
    "affected": [
        {
            "package": {"name": "urllib3", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.19"}]}],
            "database_specific": {"cvss": {"score": 4.4, "severity": "MEDIUM"}},
        }
    ],
    "database_specific": {"cwe_ids": ["CWE-200"], "severity": "MODERATE"},
}

# Shape with ONLY the CVSS vector string (no numeric in database_specific).
OSV_VECTOR_ONLY_SHAPE = {
    "id": "GHSA-test-vector-only",
    "summary": "Test vuln with only vector score.",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    ],
    "affected": [{"package": {"name": "x", "ecosystem": "PyPI"}, "ranges": []}],
}

# Shape with no severity[] and no numeric — only the string label fallback.
OSV_LABEL_ONLY_SHAPE = {
    "id": "GHSA-test-label-only",
    "summary": "Test vuln with only severity label.",
    "affected": [{"package": {"name": "x", "ecosystem": "PyPI"}, "ranges": []}],
    "database_specific": {"severity": "HIGH"},
}

# Shape with summary empty but long markdown details.
OSV_DETAILS_FALLBACK_SHAPE = {
    "id": "GHSA-test-details",
    "summary": "",
    "details": (
        "### Summary\n\n"
        "The `requests` library does not enforce strict timeouts on streaming downloads, "
        "allowing slow-loris style attacks.\n\n"
        "### Mitigation\n\nApply patch in 2.31.0."
    ),
    "severity": [{"type": "CVSS_V3", "score": "5.0"}],
    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "ranges": []}],
}


# ---------------------------------------------------------------------------
# Bug 1: CVSS score extraction
# ---------------------------------------------------------------------------

def test_cvss_score_from_affected_database_specific_takes_priority():
    # Priority 1: numeric in affected[].database_specific.cvss.score wins
    # even when severity[].score has a CVSS vector.
    assert extract_cvss_score(OSV_URLLIB3_REAL_SHAPE) == 4.4


def test_cvss_score_parses_v31_vector_string():
    # Priority 2: no numeric available, parse the vector. The well-known
    # 9.8 critical vector should round-trip to 9.8.
    score = extract_cvss_score(OSV_VECTOR_ONLY_SHAPE)
    assert score is not None
    assert 9.7 <= score <= 9.9  # spec-compliant 9.8 ± rounding tolerance


def test_cvss_score_parses_v40_vector_string():
    vuln = {
        "id": "GHSA-test-cvss4",
        "summary": "test",
        "severity": [{
            "type": "CVSS_V4",
            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        }],
        "affected": [{"package": {"name": "x", "ecosystem": "PyPI"}, "ranges": []}],
    }
    score = extract_cvss_score(vuln)
    # CVSS v4 — requires the `cvss` library to parse. Skip cleanly if missing.
    try:
        import cvss  # noqa: F401
    except ImportError:
        assert score is None
        return
    assert score is not None
    assert 9.0 <= score <= 9.5


def test_cvss_score_falls_back_to_database_specific_severity_label():
    assert extract_cvss_score(OSV_LABEL_ONLY_SHAPE) == 7.5  # HIGH anchor


def test_cvss_score_label_fallback_handles_moderate_and_low():
    vuln_mod = {"id": "x", "affected": [], "database_specific": {"severity": "MODERATE"}}
    vuln_low = {"id": "x", "affected": [], "database_specific": {"severity": "LOW"}}
    assert extract_cvss_score(vuln_mod) == 5.5
    assert extract_cvss_score(vuln_low) == 3.0


def test_cvss_score_returns_none_when_nothing_extractable():
    vuln = {"id": "x", "summary": "test", "affected": [], "database_specific": {}}
    assert extract_cvss_score(vuln) is None


def test_cvss_vector_parser_directly_round_trips_critical():
    # The canonical 9.8 critical RCE vector.
    score = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score is not None
    assert 9.7 <= score <= 9.9


def test_cvss_vector_parser_rejects_garbage():
    assert _parse_cvss_vector("not a vector") is None
    assert _parse_cvss_vector("") is None
    assert _parse_cvss_vector(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Bug 2: summary extraction
# ---------------------------------------------------------------------------

def test_summary_extraction_prefers_summary_over_details():
    summary = extract_vuln_summary(OSV_URLLIB3_REAL_SHAPE)
    assert summary.startswith("urllib3's Proxy-Authorization")
    # Truncated to 200 by default
    assert len(summary) <= 200


def test_summary_extraction_falls_back_to_details_when_summary_empty():
    summary = extract_vuln_summary(OSV_DETAILS_FALLBACK_SHAPE)
    # Markdown headers stripped, first paragraph extracted
    assert "#" not in summary
    assert "requests" in summary.lower()
    assert "library does not enforce" in summary


def test_summary_extraction_returns_explicit_marker_when_nothing_available():
    vuln = {"id": "GHSA-empty"}
    summary = extract_vuln_summary(vuln)
    assert "GHSA-empty" in summary
    assert "No summary" in summary


def test_finding_description_contains_real_text_not_placeholder():
    # Full integration: a real-shape vuln yields a readable description.
    pkg = _pkg(name="urllib3", version="1.26.18")
    response = {"results": [{"vulns": [OSV_URLLIB3_REAL_SHAPE]}]}
    with patch(
        "nodes.cve_node._query_osv_batch", new=AsyncMock(return_value=response)
    ):
        result = _run(cve_node(_state(packages=[pkg])))

    assert len(result["cve_findings"]) == 1
    f = result["cve_findings"][0]
    assert "No summary" not in f["description"]
    assert "GHSA-2xpw-w6gg-jr37" in f["description"]
    assert "Proxy-Authorization" in f["description"]
    # Severity comes from priority-1 path (4.4 → MEDIUM)
    assert f["severity"] == RiskLevel.MEDIUM
    # Citation excerpt also has real text, bounded at 100
    cit = f["citations"][0]
    assert cit["excerpt"].startswith("urllib3's")
    assert len(cit["excerpt"]) <= 100


def test_batch_returns_only_id_stubs_enrichment_provides_full_records():
    """
    Real OSV /v1/querybatch returns only {"id": ...} per vuln — no
    severity, no summary, no affected. The enrichment step fetches the
    full record from /v1/vulns/{id}. When enriched data is present,
    findings must use it (not fall back to the stub's empty fields).
    """
    pkg = _pkg(name="urllib3", version="1.26.18")
    stub_response = {"results": [{"vulns": [{"id": "GHSA-2xpw-w6gg-jr37"}]}]}
    enriched = {"GHSA-2xpw-w6gg-jr37": OSV_URLLIB3_REAL_SHAPE}

    with patch(
        "nodes.cve_node._query_osv_batch", new=AsyncMock(return_value=stub_response)
    ), patch(
        "nodes.cve_node._enrich_vulns", new=AsyncMock(return_value=enriched)
    ):
        result = _run(cve_node(_state(packages=[pkg])))

    assert len(result["cve_findings"]) == 1
    f = result["cve_findings"][0]
    # Enrichment data drove BOTH the severity (4.4 → MEDIUM) and the
    # readable description (real summary, not "No summary available").
    assert f["severity"] == RiskLevel.MEDIUM
    assert "Proxy-Authorization" in f["description"]
    assert "No summary" not in f["description"]


def test_enrichment_failure_does_not_break_scan():
    """When the per-vuln fetch fails entirely, the scan continues with
    whatever stub data the batch returned."""
    pkg = _pkg(name="urllib3", version="1.26.18")
    stub_response = {"results": [{"vulns": [{"id": "GHSA-x"}]}]}

    async def boom(_ids):
        raise RuntimeError("OSV down")

    with patch(
        "nodes.cve_node._query_osv_batch", new=AsyncMock(return_value=stub_response)
    ), patch("nodes.cve_node._enrich_vulns", side_effect=boom):
        result = _run(cve_node(_state(packages=[pkg])))

    # Still produced a finding from the stub; logged the enrichment failure.
    assert len(result["cve_findings"]) == 1
    assert any("enrichment failed" in e for e in result["errors"])


def test_finding_built_from_vector_only_vuln_has_correct_severity():
    pkg = _pkg(name="x", version="1.0")
    response = {"results": [{"vulns": [OSV_VECTOR_ONLY_SHAPE]}]}
    with patch(
        "nodes.cve_node._query_osv_batch", new=AsyncMock(return_value=response)
    ):
        result = _run(cve_node(_state(packages=[pkg])))

    f = result["cve_findings"][0]
    # Parsed CVSS 9.8 → CRITICAL
    assert f["severity"] == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# raw_osv_records + Finding contextualization-field initialization
# ---------------------------------------------------------------------------

def test_cve_node_populates_raw_osv_records_keyed_by_finding_id():
    """RiskNode needs raw OSV records to ground use-case contextualization."""
    with patch("nodes.cve_node._query_osv_batch",
               new=AsyncMock(return_value=_osv_response_with_django_vuln())):
        result = _run(cve_node(_state()))

    assert "raw_osv_records" in result
    f = result["cve_findings"][0]
    assert f["finding_id"] in result["raw_osv_records"]
    assert result["raw_osv_records"][f["finding_id"]]["id"] == "GHSA-qm57-vhq3-3fwf"


def test_cve_node_returns_empty_raw_osv_records_when_no_packages():
    with patch("nodes.cve_node._query_osv_batch",
               new=AsyncMock(return_value={"results": []})):
        result = _run(cve_node(_state(packages=[])))
    assert result["raw_osv_records"] == {}


def test_findings_carry_contextualization_fields_initialized_to_none():
    """CVENode initializes the two new Finding fields to None; RiskNode populates."""
    with patch("nodes.cve_node._query_osv_batch",
               new=AsyncMock(return_value=_osv_response_with_django_vuln())):
        result = _run(cve_node(_state()))
    f = result["cve_findings"][0]
    assert f["contextualized_severity"] is None
    assert f["contextualization_rationale"] is None


def test_cve_node_return_dict_contains_raw_osv_records_for_multiple_packages():
    """
    Regression test for a bug where CVENode built raw_osv_records
    locally but forgot to include it in its return dict. RiskNode then
    saw an empty {} via state.update(...) and skipped every
    HIGH/CRITICAL contextualization. The contract is: raw_osv_records
    MUST appear in the return dict, keyed by finding_id, with each
    value being the full OSV vuln record (not just an id reference).
    """
    pkgs = [_pkg("django", "4.2.3"), _pkg("requests", "2.28.0")]
    requests_vuln = {
        "id": "GHSA-requests-test",
        "summary": "Test vuln in requests with full body.",
        "severity": [{"type": "CVSS_V3", "score": "5.0"}],
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}],
        }],
    }
    response = {"results": [
        {"vulns": [VULN_DJANGO]},
        {"vulns": [requests_vuln]},
    ]}
    with patch("nodes.cve_node._query_osv_batch",
               new=AsyncMock(return_value=response)):
        result = _run(cve_node(_state(packages=pkgs)))

    # Contract: the field is present on the return dict.
    assert "raw_osv_records" in result, (
        f"raw_osv_records missing from return dict: keys={list(result.keys())}"
    )
    raw = result["raw_osv_records"]

    # Exactly one record per finding, keyed by finding_id.
    finding_ids = {f["finding_id"] for f in result["cve_findings"]}
    assert set(raw.keys()) == finding_ids, (
        f"key mismatch: extra={set(raw.keys()) - finding_ids}, "
        f"missing={finding_ids - set(raw.keys())}"
    )
    assert len(raw) == 2

    # Each value is the FULL OSV vuln object, not a {"id": ...} stub.
    for vuln in raw.values():
        assert isinstance(vuln, dict)
        assert vuln.get("id"), "raw record missing id"
        # The substantive fields that distinguish a full record from a stub.
        assert vuln.get("summary") or vuln.get("details") or vuln.get("affected"), (
            f"raw record looks like a stub, not a full vuln: {vuln}"
        )

    # The matched ids should be exactly the input vuln ids — no scrambling.
    assert {v["id"] for v in raw.values()} == {
        "GHSA-qm57-vhq3-3fwf", "GHSA-requests-test",
    }
