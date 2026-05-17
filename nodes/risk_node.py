"""
nodes/risk_node.py
==================
Policy enforcement and routing for the SignedOff compliance agent.

Fan-in after parallel LicenseNode + CVENode. Merges all findings into a
single risk_matrix, applies POLICY.yml thresholds to route each finding,
checks L2 decision memory for prior human decisions, sets per-package
license_risk and security_risk dimensions (NEVER combined into a
single number), and generates a non-technical executive summary via
LLM grounded on aggregate counts only.

ROUTING ORDER (must match this sequence):
  1. Hard override: findings backed only by LLM_INFERENCE or NONE_FOUND
     citations always route to HUMAN_REVIEW. Cannot be overridden by
     policy thresholds.
  2. severity below auto_accept_below → ACCEPTED (auto)
  3. severity below auto_remediate_below → AUTO_REMEDIATE
  4. else → HUMAN_REVIEW

L2 MEMORY:
  After routing, every finding still in HUMAN_REVIEW gets a lookup. On
  a hit, prior_decision is attached. If the policy mode for that
  severity is auto_accept_with_log, the finding is flipped to ACCEPTED
  with decided_by="auto_l2" and an l2_auto_accepted audit event is
  emitted — never silently. The audit-trail entry IS the artifact
  recording that no human re-reviewed the finding.

EXECUTIVE SUMMARY:
  The LLM receives ONLY aggregate counts and use_case — never raw CVE
  IDs, package names, or finding text. The prompt forbids referencing
  anything outside the data dict. Failure falls back to a deterministic
  template built from the same data.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from agent_state import (
    AgentState,
    CitationSource,
    DecisionStatus,
    Finding,
    PackageRecord,
    RemediationType,
    RiskLevel,
)


ALLOWED_CTX_ACTION_TYPES = {
    "version_bump",
    "accept_as_is",
    "compensating_control",
    "monitor",
}

_CTX_ACTION_TYPE_MAP = {
    "version_bump": RemediationType.VERSION_BUMP,
    "accept_as_is": RemediationType.ACCEPT_AS_IS,
    "compensating_control": RemediationType.COMPENSATING_CONTROL,
    "monitor": RemediationType.MONITOR,
}


LLM_MODEL = "claude-sonnet-4-6"
CVE_CONTEXT_CONCURRENCY = 5

SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]

DEFAULT_THRESHOLDS: dict[str, dict[str, str]] = {
    "license": {"auto_remediate_below": "medium", "auto_accept_below": "low"},
    "security": {"auto_remediate_below": "high", "auto_accept_below": "low"},
}

DEFAULT_PRIOR_DECISIONS: dict[str, dict[str, str]] = {
    "critical": {"mode": "always_resurface"},
    "high": {"mode": "show_for_confirmation"},
    "medium": {"mode": "show_for_confirmation"},
    "low": {"mode": "auto_accept_with_log"},
    "none": {"mode": "auto_accept_with_log"},
}

WEAK_CITATION_SOURCES: set[CitationSource] = {
    CitationSource.LLM_INFERENCE,
    CitationSource.NONE_FOUND,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_value(level: Any) -> str:
    if isinstance(level, RiskLevel):
        return level.value
    return str(level)


def _severity_idx(level: Any) -> int:
    value = _severity_value(level)
    try:
        return SEVERITY_ORDER.index(value)
    except ValueError:
        # Unknown severity string — treat conservatively as MEDIUM so it
        # routes through human review rather than silently auto-resolving.
        return SEVERITY_ORDER.index("medium")


def _max_severity_of_findings(findings: list[Finding]) -> RiskLevel:
    if not findings:
        return RiskLevel.NONE
    best_idx = max(_severity_idx(f["severity"]) for f in findings)
    return RiskLevel(SEVERITY_ORDER[best_idx])


def _max_severity(a: Any, b: Any) -> RiskLevel:
    """Return the more severe of two RiskLevel-or-string values."""
    idx_a = _severity_idx(a)
    idx_b = _severity_idx(b)
    return RiskLevel(SEVERITY_ORDER[max(idx_a, idx_b)])


def _map_severity_string(value: str) -> RiskLevel:
    """Map a lowercase severity string to RiskLevel; defaults to MEDIUM."""
    try:
        return RiskLevel(value.lower())
    except (ValueError, AttributeError):
        return RiskLevel.MEDIUM


def _effective_severity(finding: Finding) -> Any:
    """
    For CVE findings, route on max(raw severity, contextualized_severity).
    The LLM can never downgrade a CRITICAL past the human-review gate —
    if EITHER raw or contextualized is HIGH/CRITICAL we always route to
    HUMAN_REVIEW. License findings route on raw severity only.
    """
    finding_type = finding.get("finding_type", "")
    raw = finding["severity"]
    ctx = finding.get("contextualized_severity")
    if finding_type.startswith("cve") and ctx is not None:
        return _max_severity(raw, ctx)
    return raw


def route_finding(finding: Finding, policy: dict) -> DecisionStatus:
    """
    Apply rules 1–4 in order. Returns the DecisionStatus to assign.
    """
    citations = finding.get("citations") or []
    sources = {c["source"] for c in citations}

    # Rule 1: hard override — empty citations or only weak citations escalate.
    if not sources or sources.issubset(WEAK_CITATION_SOURCES):
        return DecisionStatus.HUMAN_REVIEW

    finding_type = finding.get("finding_type", "")
    is_license = finding_type.startswith("license_")
    bucket = "license" if is_license else "security"

    thresholds_root = policy.get("thresholds") or DEFAULT_THRESHOLDS
    thresholds = thresholds_root.get(bucket) or DEFAULT_THRESHOLDS[bucket]

    severity_idx = _severity_idx(_effective_severity(finding))
    auto_remediate_idx = _severity_idx(
        thresholds.get("auto_remediate_below", DEFAULT_THRESHOLDS[bucket]["auto_remediate_below"])
    )
    auto_accept_idx = _severity_idx(
        thresholds.get("auto_accept_below", DEFAULT_THRESHOLDS[bucket]["auto_accept_below"])
    )

    if severity_idx < auto_accept_idx:
        return DecisionStatus.ACCEPTED
    if severity_idx < auto_remediate_idx:
        return DecisionStatus.AUTO_REMEDIATE
    return DecisionStatus.HUMAN_REVIEW


# ---------------------------------------------------------------------------
# L2 cache (lazy + defensive)
# ---------------------------------------------------------------------------

def _try_get_l2_memory():
    try:
        from cache.l2_decision_memory import l2_memory
        return l2_memory, None
    except Exception as exc:
        return None, f"L2 decision memory unavailable: {exc}"


def _l2_mode_for_severity(policy: dict, severity: RiskLevel) -> str:
    prior_decisions = policy.get("prior_decisions") or DEFAULT_PRIOR_DECISIONS
    sev_value = _severity_value(severity)
    entry = prior_decisions.get(sev_value) or {}
    return entry.get("mode") or "show_for_confirmation"


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

EXECUTIVE_SUMMARY_PROMPT = """Write a 2-3 sentence executive summary of this compliance scan
for a non-technical audience. Be specific and factual. Use only the data below.

{summary_json}

Do not mention any CVE IDs, package names, or technical details not present
in the data above. Do not make recommendations beyond what the data shows."""


def _count_by_severity(findings: list[Finding], severity_value: str) -> int:
    return sum(1 for f in findings if _severity_value(f["severity"]) == severity_value)


def _summarize_finding_for_llm(finding: Finding) -> dict:
    return {
        "type": finding.get("finding_type"),
        "severity": _severity_value(finding["severity"]),
        "decision_status": (
            finding["decision_status"].value
            if isinstance(finding["decision_status"], DecisionStatus)
            else finding["decision_status"]
        ),
    }


def _build_summary_data(
    packages: list[PackageRecord],
    all_findings: list[Finding],
    resolved_findings: list[Finding],
    pending_human_review: list[Finding],
    use_case: str,
) -> dict:
    return {
        "packages_total": len(packages),
        "findings_total": len(all_findings),
        "critical_count": _count_by_severity(all_findings, "critical"),
        "high_count": _count_by_severity(all_findings, "high"),
        "medium_count": _count_by_severity(all_findings, "medium"),
        "low_count": _count_by_severity(all_findings, "low"),
        "auto_resolved": len(resolved_findings),
        "awaiting_review": len(pending_human_review),
        "use_case": use_case,
        "top_findings": [_summarize_finding_for_llm(f) for f in all_findings[:3]],
    }


def _template_summary(d: dict) -> str:
    return (
        f"Scanned {d['packages_total']} packages as a {d['use_case']} application "
        f"and produced {d['findings_total']} findings "
        f"({d['critical_count']} critical, {d['high_count']} high, "
        f"{d['medium_count']} medium, {d['low_count']} low). "
        f"{d['auto_resolved']} were resolved automatically per policy and "
        f"{d['awaiting_review']} require human review."
    )


async def _call_llm_for_summary(summary_data: dict) -> str:
    """
    Ask Claude to write a non-technical executive summary.

    The prompt receives ONLY the aggregate dict — no raw finding text,
    no CVE IDs, no package names beyond what's in top_findings (which
    itself is sanitized to type/severity/status only). anthropic is
    imported lazily so the module loads without it (tests mock this
    function entirely).
    """
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic()
    response = await client.messages.create(
        model=LLM_MODEL,
        max_tokens=400,
        messages=[
            {
                "role": "user",
                "content": EXECUTIVE_SUMMARY_PROMPT.format(
                    summary_json=json.dumps(summary_data, indent=2)
                ),
            }
        ],
    )
    return response.content[0].text.strip()


# ---------------------------------------------------------------------------
# CVE use-case contextualization
# ---------------------------------------------------------------------------

CVE_USE_CASE_DESCRIPTIONS = {
    "saas": (
        "Software delivered as a service over the network. "
        "Accepts user input via HTTP. Public-facing."
    ),
    "internal": (
        "Internal tooling for employees only. Not exposed to the public "
        "internet. Trusted users only."
    ),
    "distributed_binary": (
        "Shipped to end users as an installable package. "
        "Runs on user-controlled machines."
    ),
}


# Few-shot prompt template. Uses str.format() rather than an f-string
# because the JSON examples contain literal { } that would otherwise need
# doubling. Format slots: cve_record_json, package, version,
# raw_severity, use_case, use_case_desc.
_CVE_CONTEXT_PROMPT_TEMPLATE = """You are a security analyst evaluating whether a CVE's risk is materially different from its raw CVSS severity in a specific deployment context, and recommending a context-aware action.

Here are four examples demonstrating the kind of analysis expected.
Match the depth, specificity, and calibrated confidence shown.

============================================================
EXAMPLE 1 — VERSION_BUMP (attack vector applies directly)
============================================================
CVE record:
{{
  "id": "GHSA-example-django-sqli",
  "summary": "SQL injection via QuerySet.annotate() with crafted column aliases on MySQL/MariaDB",
  "details": "An attacker with ability to influence column alias names in ORM queries can inject arbitrary SQL.",
  "affected_packages": [{{"name": "Django"}}],
  "cwe_ids": ["CWE-89"]
}}
Package: Django 4.2.3
Raw CVSS severity: critical
Use case: saas — Software delivered as a service over the network. Accepts user input via HTTP. Public-facing.

Analysis output:
{{
  "reachable": "yes",
  "contextualized_severity": "critical",
  "rationale": "The attack exploits user-controllable input flowing into ORM queries, which is standard behavior in any SaaS application using Django. The use case directly matches the attack vector. Confidence: high.",
  "key_factor": "user input reaches ORM query construction",
  "recommended_action_type": "version_bump",
  "contextualized_recommendation": "Upgrade Django to a version that patches GHSA-example-django-sqli. The vulnerability is directly reachable in this SaaS deployment and no contextual factors reduce the risk."
}}

============================================================
EXAMPLE 2 — ACCEPT_AS_IS (attack vector does not reach this deployment)
============================================================
CVE record:
{{
  "id": "GHSA-example-pillow-bof",
  "summary": "Buffer overflow in Pillow's _imagingcms module when processing malformed ICC color profiles in user-uploaded images",
  "details": "An attacker who can supply a crafted image file can trigger memory corruption.",
  "affected_packages": [{{"name": "Pillow"}}],
  "cwe_ids": ["CWE-122"]
}}
Package: Pillow 9.5.0
Raw CVSS severity: high
Use case: internal — Internal tooling for employees only. Not exposed to the public internet. Trusted users only.

Analysis output:
{{
  "reachable": "no",
  "contextualized_severity": "low",
  "rationale": "The attack requires processing untrusted user-uploaded image files. The internal use case describes trusted users only with no public image upload surface, so the vulnerable code path is not reachable. Confidence: high.",
  "key_factor": "no untrusted image input surface",
  "recommended_action_type": "accept_as_is",
  "contextualized_recommendation": "Accept this finding as low risk for the current deployment. The attack requires untrusted image input, which is not present in an internal-tooling use case. Document the acceptance rationale and re-evaluate if the deployment model changes."
}}

============================================================
EXAMPLE 3 — COMPENSATING_CONTROL (vector applies, infra mitigation available)
============================================================
CVE record:
{{
  "id": "GHSA-example-urllib3-decomp",
  "summary": "urllib3 streaming API allows unbounded decompression of attacker-controlled responses, causing DoS",
  "details": "When making outbound HTTP requests with streaming enabled, urllib3 does not bound the decompression of compressed responses from untrusted servers.",
  "affected_packages": [{{"name": "urllib3"}}],
  "cwe_ids": ["CWE-409"]
}}
Package: urllib3 1.26.20
Raw CVSS severity: high
Use case: saas — Software delivered as a service over the network. Accepts user input via HTTP. Public-facing.

Analysis output:
{{
  "reachable": "yes",
  "contextualized_severity": "high",
  "rationale": "The SaaS application likely makes outbound HTTP requests to URLs that may be influenced by user input, exposing the unbounded decompression path. Confidence: high.",
  "key_factor": "outbound requests to attacker-influenced URLs",
  "recommended_action_type": "compensating_control",
  "contextualized_recommendation": "Until urllib3 can be upgraded, route outbound HTTP traffic through an egress proxy that enforces response size limits, or restrict outbound destinations to an allowlist. This mitigates the decompression-bomb vector at the network layer."
}}

============================================================
EXAMPLE 4 — MONITOR (conditional on application-specific code)
============================================================
CVE record:
{{
  "id": "GHSA-example-django-path",
  "summary": "Django Path Traversal vulnerability in custom Storage subclasses",
  "details": "Custom Storage subclasses that override generate_filename() without proper validation are vulnerable to path traversal via crafted filename inputs. Built-in Django storage classes are not affected.",
  "affected_packages": [{{"name": "Django"}}],
  "cwe_ids": ["CWE-22"]
}}
Package: Django 4.2.3
Raw CVSS severity: high
Use case: saas — Software delivered as a service over the network. Accepts user input via HTTP. Public-facing.

Analysis output:
{{
  "reachable": "partial",
  "contextualized_severity": "medium",
  "rationale": "Exploitability depends entirely on whether the application implements a custom Storage subclass that overrides generate_filename() without validation. Built-in Django storage is unaffected. The use case does not determine reachability — the application code does. Confidence: medium.",
  "key_factor": "depends on custom Storage subclass usage",
  "recommended_action_type": "monitor",
  "contextualized_recommendation": "Audit your codebase for custom Storage subclasses that override generate_filename(). If none exist, defer this finding with documented rationale. If any do exist, treat as a version_bump priority. Re-evaluate this finding if Storage-related code is added in the future."
}}

============================================================
NOW CONTEXTUALIZE THIS CVE
============================================================
CVE record:
{cve_record_json}

Package: {package} {version}
Raw CVSS severity: {raw_severity}
Use case: {use_case} — {use_case_desc}

Respond with JSON matching the same field shape as the examples above:
- reachable: one of "yes", "no", "partial", "unknown"
- contextualized_severity: one of "critical", "high", "medium", "low", "none"
- rationale: one to two sentences ending with "Confidence: {{high|medium|low}}."
- key_factor: under 10 words, the single most important reasoning factor
- recommended_action_type: EXACTLY one of "version_bump", "accept_as_is", "compensating_control", "monitor"
- contextualized_recommendation: one to two sentences explaining what the reviewer should do

CRITICAL CONSTRAINTS:
- Use ONLY information from the CVE record above. Do not reference vulnerabilities, packages, attack vectors, or code paths not in the input.
- recommended_action_type MUST be one of the four values listed above. Do not invent new values. Do not use any other RemediationType.
- If the record is too thin to make a contextual judgment, return contextualized_severity equal to raw_severity, recommended_action_type "version_bump", and rationale "Insufficient information to contextualize. Confidence: low."
"""


async def _call_llm_for_cve_context(
    vuln: dict,
    package: str,
    version: str,
    raw_severity: str,
    use_case: str,
) -> Optional[dict]:
    """
    Ask Claude to contextualize a CVE against the declared use_case.

    GROUNDING DISCIPLINE: the LLM receives the actual OSV record fields
    needed to reason — id, summary, details, affected ranges, CWE ids,
    references. It is explicitly instructed NOT to use any knowledge
    outside that grounding data. Same pattern LicenseNode uses for
    SPDX-grounded license reasoning.

    Returns dict {"contextualized_severity", "rationale", ...} on
    success, or None on any failure (defensive — the finding is left
    unchanged).
    """
    try:
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic()
    except Exception:
        return None

    grounded_input = {
        "id": vuln.get("id"),
        "summary": vuln.get("summary"),
        "details": (vuln.get("details") or "")[:1500],
        "affected_packages": [
            {
                "name": (a.get("package") or {}).get("name"),
                "ranges": a.get("ranges", []),
            }
            for a in (vuln.get("affected") or [])
        ],
        "cwe_ids": (vuln.get("database_specific") or {}).get("cwe_ids", []),
        "references": [
            r.get("url") for r in (vuln.get("references") or [])[:5]
        ],
    }
    use_case_desc = CVE_USE_CASE_DESCRIPTIONS.get(use_case, "unspecified")

    prompt = _CVE_CONTEXT_PROMPT_TEMPLATE.format(
        cve_record_json=json.dumps(grounded_input, indent=2),
        package=package,
        version=version,
        raw_severity=raw_severity,
        use_case=use_case,
        use_case_desc=use_case_desc,
    )

    try:
        response = await client.messages.create(
            model=LLM_MODEL,
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_text = response.content[0].text.strip()

        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        result = json.loads(raw_text)
    except Exception:
        return None

    # Schema validation. Any failure → None so the finding is left
    # unchanged and llm_call_failures is bumped upstream.
    required_keys = (
        "contextualized_severity",
        "rationale",
        "recommended_action_type",
        "contextualized_recommendation",
    )
    if not all(k in result for k in required_keys):
        return None
    if result["contextualized_severity"] not in (
        "critical", "high", "medium", "low", "none",
    ):
        return None
    if result["recommended_action_type"] not in ALLOWED_CTX_ACTION_TYPES:
        return None
    rec = result.get("contextualized_recommendation")
    if not isinstance(rec, str) or len(rec.strip()) < 20:
        return None
    return result


def _hash_payload(data: dict) -> str:
    serializable = {
        k: (v.value if isinstance(v, CitationSource) else v)
        for k, v in data.items()
        if k != "content_hash"
    }
    return hashlib.sha256(
        json.dumps(serializable, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _build_contextualization_citation(rationale: str) -> dict:
    data: dict[str, Any] = {
        "source": CitationSource.LLM_INFERENCE,
        "url": None,
        "identifier": None,
        "excerpt": (rationale or "")[:100],
        "retrieved_at": _now_iso(),
        "confidence": "inferred",
        "validated": False,
        "validation_method": "not_validated",
    }
    data["content_hash"] = _hash_payload(data)
    return data


def _build_contextualized_remediation(result: dict, use_case: str) -> dict:
    """
    Build a context-aware Remediation from a successful LLM contextualization
    result. Each remediation gets its OWN LLM_INFERENCE citation so the
    Finding's contextualization citation and this remediation's citation
    serve distinct audit roles.
    """
    recommendation = result["contextualized_recommendation"]
    remediation_citation: dict[str, Any] = {
        "source": CitationSource.LLM_INFERENCE,
        "url": None,
        "identifier": None,
        "excerpt": recommendation[:100],
        "retrieved_at": _now_iso(),
        "confidence": "inferred",
        "validated": False,
        "validation_method": "not_validated",
    }
    remediation_citation["content_hash"] = _hash_payload(remediation_citation)

    remediation_type = _CTX_ACTION_TYPE_MAP[result["recommended_action_type"]]
    key_factor = result.get("key_factor") or "unspecified"

    return {
        "type": remediation_type,
        "description": recommendation,
        "target_package": None,
        "target_version": None,
        "confidence": "low",
        "rationale": (
            f"Context-aware recommendation based on use_case={use_case}. "
            f"Key factor: {key_factor}. "
            "Reviewer should verify the analysis applies to their codebase "
            "before acting."
        ),
        "tradeoffs": None,
        "citations": [remediation_citation],
    }


async def _contextualize_high_severity_cves(
    findings: list[Finding],
    use_case: str,
    raw_osv_records: dict,
) -> tuple[list[Finding], list[dict], dict]:
    """
    Contextualize HIGH/CRITICAL CVE findings against the declared
    use_case via LLM. Mutates `findings` in place and returns:
      (findings, audit_events_for_each_evaluation, summary_stats)

    LOW/MEDIUM findings pass through untouched — policy auto-routes
    them anyway so LLM tokens spent here would have no downstream impact.
    License findings are never contextualized; LicenseNode already
    grounds them on SPDX + use_case at creation time.

    Defensive: on any LLM error the finding is returned unchanged. The
    contextualization NEVER deletes or overwrites raw severity — it only
    adds optional adjunct fields.
    """
    sem = asyncio.Semaphore(CVE_CONTEXT_CONCURRENCY)
    audit_events: list[dict] = []
    stats = {
        "findings_evaluated": 0,
        "downgraded_count": 0,
        "unchanged_count": 0,
        "escalated_count": 0,
        "llm_call_failures": 0,
    }
    action_type_distribution: dict[str, int] = {
        action: 0 for action in ALLOWED_CTX_ACTION_TYPES
    }

    async def contextualize_one(finding: Finding) -> Finding:
        finding_type = finding.get("finding_type", "")
        if not finding_type.startswith("cve"):
            return finding
        sev_str = _severity_value(finding["severity"])
        if sev_str not in ("high", "critical"):
            return finding

        raw_record = (raw_osv_records or {}).get(finding["finding_id"])
        if not raw_record:
            return finding

        stats["findings_evaluated"] += 1
        async with sem:
            result = await _call_llm_for_cve_context(
                vuln=raw_record,
                package=finding["package"],
                version=finding["version"],
                raw_severity=sev_str,
                use_case=use_case,
            )

        if result is None:
            stats["llm_call_failures"] += 1
            return finding

        ctx_sev = _map_severity_string(result["contextualized_severity"])
        finding["contextualized_severity"] = ctx_sev
        finding["contextualization_rationale"] = result.get("rationale")

        # Citation #1: backs the contextualization analysis on the Finding.
        finding.setdefault("citations", []).append(
            _build_contextualization_citation(result.get("rationale", ""))
        )

        # Append a parallel context-aware Remediation alongside the
        # existing version_bump (which stays untouched). The new
        # remediation gets its OWN LLM_INFERENCE citation — a separate
        # audit artifact from the Finding's contextualization citation.
        contextualized_remediation = _build_contextualized_remediation(
            result, use_case
        )
        finding.setdefault("remediations", []).append(contextualized_remediation)

        action_type_str = result["recommended_action_type"]
        action_type_distribution[action_type_str] = (
            action_type_distribution.get(action_type_str, 0) + 1
        )

        raw_idx = _severity_idx(finding["severity"])
        ctx_idx = _severity_idx(ctx_sev)
        if ctx_idx < raw_idx:
            stats["downgraded_count"] += 1
        elif ctx_idx > raw_idx:
            stats["escalated_count"] += 1
        else:
            stats["unchanged_count"] += 1

        audit_events.append({
            "timestamp": _now_iso(),
            "event_type": "cve_contextualized",
            "payload": {
                "finding_id": finding["finding_id"],
                "package": finding["package"],
                "version": finding["version"],
                "raw_severity": sev_str,
                "contextualized_severity": _severity_value(ctx_sev),
                "use_case": use_case,
                "key_factor": result.get("key_factor"),
                "recommended_action_type": action_type_str,
            },
        })

        return finding

    results = await asyncio.gather(
        *(contextualize_one(f) for f in findings),
        return_exceptions=True,
    )

    final: list[Finding] = []
    for original, res in zip(findings, results):
        if isinstance(res, Exception):
            stats["llm_call_failures"] += 1
            final.append(original)
        else:
            final.append(res)

    summary_payload = dict(stats)
    summary_payload["action_type_distribution"] = action_type_distribution
    audit_events.append({
        "timestamp": _now_iso(),
        "event_type": "cve_contextualization_complete",
        "payload": summary_payload,
    })
    return final, audit_events, stats


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def _risk_matrix_complete_event(
    total_findings: int,
    human_review_count: int,
    auto_remediate_count: int,
    auto_accept_count: int,
    l2_hits: int,
) -> dict:
    return {
        "timestamp": _now_iso(),
        "event_type": "risk_matrix_complete",
        "payload": {
            "total_findings": total_findings,
            "human_review_count": human_review_count,
            "auto_remediate_count": auto_remediate_count,
            "auto_accept_count": auto_accept_count,
            "l2_hits": l2_hits,
        },
    }


def _l2_auto_accepted_event(finding: Finding, prior: dict) -> dict:
    return {
        "timestamp": _now_iso(),
        "event_type": "l2_auto_accepted",
        "payload": {
            "finding_id": finding["finding_id"],
            "package": finding["package"],
            "version": finding["version"],
            "original_decided_by": prior.get("decided_by"),
            "original_decided_at": prior.get("decided_at"),
        },
    }


# ---------------------------------------------------------------------------
# Main node
# ---------------------------------------------------------------------------

async def risk_node(state: AgentState) -> dict:
    license_findings: list[Finding] = list(state.get("license_findings") or [])
    cve_findings: list[Finding] = list(state.get("cve_findings") or [])
    packages: list[PackageRecord] = list(state.get("packages") or [])
    use_case: str = state.get("use_case", "")
    policy: dict = state.get("policy") or {}
    policy_hash: str = policy.get("policy_hash") or "unknown"
    raw_osv_records: dict = state.get("raw_osv_records") or {}

    errors: list[str] = []

    all_findings: list[Finding] = license_findings + cve_findings

    # Stable sort by severity desc — preserves intra-severity order for
    # deterministic UI ordering and reproducible tests.
    all_findings.sort(key=lambda f: -_severity_idx(f["severity"]))

    # Stage 0: contextualize HIGH/CRITICAL CVE findings against use_case.
    # LOW/MEDIUM and license findings pass through untouched. Mutates
    # findings in place and appends LLM_INFERENCE citations + audit
    # events. Defensive: failures leave findings unchanged.
    try:
        all_findings, context_events, _ctx_stats = await _contextualize_high_severity_cves(
            all_findings, use_case, raw_osv_records,
        )
    except Exception as exc:
        errors.append(f"CVE contextualization step crashed (continuing): {exc}")
        context_events = []

    # Stage 1: route every finding via policy thresholds. CVE routing
    # uses max(raw severity, contextualized_severity) — see
    # _effective_severity() — so the LLM can never downgrade a CRITICAL
    # past the human-review gate.
    decided_at_iso = _now_iso()
    for f in all_findings:
        f["decision_status"] = route_finding(f, policy)
        if f["decision_status"] in (DecisionStatus.AUTO_REMEDIATE, DecisionStatus.ACCEPTED):
            f["decided_by"] = "auto"
            f["decided_at"] = decided_at_iso

    # Stage 2: L2 decision memory.
    l2_memory, l2_warn = _try_get_l2_memory()
    if l2_warn:
        errors.append(l2_warn)

    l2_hits = 0
    l2_auto_events: list[dict] = []

    if l2_memory is not None:
        for f in all_findings:
            if f["decision_status"] != DecisionStatus.HUMAN_REVIEW:
                continue
            try:
                prior = l2_memory.get(
                    f["package"], f["version"], f["finding_type"],
                    use_case, policy_hash,
                )
            except Exception as exc:
                errors.append(
                    f"L2 lookup failed for {f.get('finding_id')}: {exc}"
                )
                continue
            if not prior:
                continue
            l2_hits += 1
            f["prior_decision"] = prior
            mode = _l2_mode_for_severity(policy, f["severity"])
            if mode == "auto_accept_with_log":
                f["decision_status"] = DecisionStatus.ACCEPTED
                f["decided_by"] = "auto_l2"
                f["decided_at"] = _now_iso()
                f["decision_rationale"] = (
                    f"Auto-applied prior decision from "
                    f"{prior.get('decided_at', '?')} by "
                    f"{prior.get('decided_by', '?')}; "
                    "policy mode = auto_accept_with_log."
                )
                l2_auto_events.append(_l2_auto_accepted_event(f, prior))
            # show_for_confirmation / always_resurface: leave HUMAN_REVIEW;
            # prior_decision is already attached so the UI can surface it.

    # Stage 3: split into pending vs resolved.
    pending_human_review: list[Finding] = []
    resolved_findings: list[Finding] = []
    for f in all_findings:
        if f["decision_status"] == DecisionStatus.HUMAN_REVIEW:
            pending_human_review.append(f)
        else:
            resolved_findings.append(f)

    # Stage 4: per-package risk dimensions. license_risk and security_risk
    # are kept SEPARATE — combining them loses signal (a package with high
    # license risk and low security risk averaged to medium tells the
    # reviewer nothing actionable).
    for pkg in packages:
        pkg_name_lc = pkg["name"].lower()
        pkg_license = [
            f for f in all_findings
            if f["package"].lower() == pkg_name_lc
            and f["finding_type"].startswith("license_")
        ]
        pkg_cve = [
            f for f in all_findings
            if f["package"].lower() == pkg_name_lc
            and f["finding_type"].startswith("cve")
        ]
        pkg["license_risk"] = _max_severity_of_findings(pkg_license)
        pkg["security_risk"] = _max_severity_of_findings(pkg_cve)

    # Stage 5: executive summary (grounded LLM, template fallback).
    summary_data = _build_summary_data(
        packages, all_findings, resolved_findings, pending_human_review, use_case
    )
    try:
        risk_summary = await _call_llm_for_summary(summary_data)
        if not risk_summary:
            raise ValueError("empty LLM response")
    except Exception as exc:
        errors.append(f"executive summary LLM call failed; using template: {exc}")
        risk_summary = _template_summary(summary_data)

    # Stage 6: audit events.
    auto_remediate_count = sum(
        1 for f in all_findings if f["decision_status"] == DecisionStatus.AUTO_REMEDIATE
    )
    auto_accept_count = sum(
        1 for f in all_findings if f["decision_status"] == DecisionStatus.ACCEPTED
    )

    audit_events: list[dict] = list(context_events)
    audit_events.append(
        _risk_matrix_complete_event(
            total_findings=len(all_findings),
            human_review_count=len(pending_human_review),
            auto_remediate_count=auto_remediate_count,
            auto_accept_count=auto_accept_count,
            l2_hits=l2_hits,
        )
    )
    audit_events.extend(l2_auto_events)

    status = "awaiting_human" if pending_human_review else "running"

    # IMPORTANT: include license_findings and cve_findings in the return
    # so the routed decision_status survives LangGraph's checkpoint
    # serialization. The Stage-1 loop above mutates finding dicts in
    # place (f["decision_status"] = route_finding(f, policy)), but those
    # mutations don't propagate to persisted state unless the affected
    # fields appear in this return dict — LangGraph re-hydrates the
    # state from the last checkpoint, not from in-memory Python
    # references. Pre-fix symptom: LicenseNode happens to write
    # decision_status=HUMAN_REVIEW directly at finding-construction
    # time (license_node.py lines 429, 555), so license findings looked
    # "correct" in /scan/results; CVENode writes the default PENDING,
    # so CVE findings were stuck at PENDING in the persisted state even
    # though pending_human_review[] (returned correctly) listed them.
    # The dashboard's decision-form gate is on decision_status =
    # "human_review", so CVE findings never showed Accept / Defer /
    # Auto-Remediate buttons. The local license_findings / cve_findings
    # lists hold the SAME mutated Finding dict references as
    # all_findings, so emitting them here picks up the routed
    # decision_status for both branches symmetrically.
    return {
        "risk_matrix": all_findings,
        "license_findings": license_findings,
        "cve_findings": cve_findings,
        "risk_summary": risk_summary,
        "pending_human_review": pending_human_review,
        "resolved_findings": resolved_findings,
        "packages": packages,
        "status": status,
        "audit_events": audit_events,
        "errors": errors,
    }
