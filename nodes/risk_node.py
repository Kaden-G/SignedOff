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
    RiskLevel,
)


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

    prompt = (
        "You are a security analyst evaluating whether a CVE's risk is "
        "materially different from its raw CVSS severity, given a specific "
        "deployment context.\n\n"
        f"Here is the CVE record:\n{json.dumps(grounded_input, indent=2)}\n\n"
        f"The package is: {package} (version {version})\n"
        f"The raw CVSS severity is: {raw_severity}\n"
        f"The deployment use case is: {use_case} — {use_case_desc}\n\n"
        "Based ONLY on the CVE record and the use case description above, answer:\n"
        "1. Is the vulnerable code path likely to be reachable in this use case? "
        "Be specific about which CVE attack vector would or would not apply.\n"
        "2. What is the contextualized severity level for THIS deployment context? "
        "Choose one: critical, high, medium, low, none\n"
        "3. One-sentence rationale, plus a confidence level (high/medium/low).\n\n"
        "Respond ONLY with JSON in this exact shape:\n"
        "{\n"
        '  "reachable": "yes|no|partial|unknown",\n'
        '  "contextualized_severity": "critical|high|medium|low|none",\n'
        '  "rationale": "One sentence. Confidence: high|medium|low.",\n'
        '  "key_factor": "Most important factor in six words or fewer."\n'
        "}\n\n"
        "CRITICAL CONSTRAINTS:\n"
        "- Do not reference any vulnerabilities, packages, or facts not present "
        "in the CVE record above.\n"
        "- Do not speculate about code paths the record does not describe.\n"
        "- If the record is too thin to make a contextual judgment, return "
        "contextualized_severity equal to the raw_severity and rationale "
        '"Insufficient information to contextualize. Confidence: low."'
    )

    try:
        response = await client.messages.create(
            model=LLM_MODEL,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_text = response.content[0].text.strip()

        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        result = json.loads(raw_text)
        if not all(k in result for k in ("contextualized_severity", "rationale")):
            return None
        if result["contextualized_severity"] not in (
            "critical", "high", "medium", "low", "none",
        ):
            return None
        return result
    except Exception:
        return None


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

        finding.setdefault("citations", []).append(
            _build_contextualization_citation(result.get("rationale", ""))
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

    audit_events.append({
        "timestamp": _now_iso(),
        "event_type": "cve_contextualization_complete",
        "payload": dict(stats),
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

    return {
        "risk_matrix": all_findings,
        "risk_summary": risk_summary,
        "pending_human_review": pending_human_review,
        "resolved_findings": resolved_findings,
        "packages": packages,
        "status": status,
        "audit_events": audit_events,
        "errors": errors,
    }
