"""
nodes/license_node.py
=====================
License compliance evaluation for the SignedOff compliance agent.

Three-stage pipeline, fast-path first:
  1. Policy fast-path: hits in policy.licenses.allowed/blocked skip the
     LLM entirely. Allowed = no Finding. Blocked = CRITICAL Finding.
  2. SPDX lookup: confirms the license exists and pulls canonical
     metadata. Misses → unknown.
  3. LLM reasoning: only for licenses in policy.licenses.requires_review
     OR licenses that passed SPDX but aren't on either list. The LLM
     ALWAYS receives the SPDX entry as grounding and is constrained to
     reason only over what we passed it.

CITATION INTEGRITY:
  - Allowed packages produce no Finding (compliant).
  - Blocked Findings carry SPDX (when known) + POLICY citations.
  - LLM-reasoned Findings ALWAYS carry both SPDX (authoritative) and
    LLM_INFERENCE (inferred) citations — never just one.
  - LLM_INFERENCE citations have url=None so the LLM has no field to
    hallucinate a URL into.
  - Unknown licenses get NONE_FOUND + POLICY citations.

CONCURRENCY:
  Per-package evaluation runs under asyncio.Semaphore(5) to cap
  concurrent LLM calls.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agent_state import (
    AgentState,
    Citation,
    CitationSource,
    DecisionStatus,
    Finding,
    PackageRecord,
    Remediation,
    RemediationType,
    RiskLevel,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SPDX_DATASET_PATH = PROJECT_ROOT / "data" / "spdx_licenses.json"
CURATED_MAPPINGS_PATH = PROJECT_ROOT / "data" / "curated_mappings.json"

LLM_CONCURRENCY = 5
LLM_MODEL = "claude-sonnet-4-6"

RISK_LEVEL_FROM_STRING: dict[str, RiskLevel] = {
    "critical": RiskLevel.CRITICAL,
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MEDIUM,
    "low": RiskLevel.LOW,
    "none": RiskLevel.NONE,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_citation(data: dict) -> str:
    serializable = {
        k: (v.value if isinstance(v, CitationSource) else v)
        for k, v in data.items()
        if k != "content_hash"
    }
    return hashlib.sha256(
        json.dumps(serializable, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Data loaders (module-level functions so tests can monkeypatch them)
# ---------------------------------------------------------------------------

def _load_json_file(path: Path, label: str) -> tuple[Optional[dict], Optional[str]]:
    if not path.exists():
        return None, f"{label} not found at {path}; continuing without it"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"{label} could not be loaded: {exc}"


def _load_spdx_dataset() -> tuple[dict, Optional[str]]:
    data, warn = _load_json_file(SPDX_DATASET_PATH, "SPDX dataset")
    return (data or {}), warn


def _load_curated_mappings() -> tuple[dict, Optional[str]]:
    data, warn = _load_json_file(CURATED_MAPPINGS_PATH, "Curated alternatives mapping")
    return (data or {}), warn


# ---------------------------------------------------------------------------
# Citation builders
# ---------------------------------------------------------------------------

def build_policy_citation(rule_path: str, excerpt: str) -> Citation:
    data: dict[str, Any] = {
        "source": CitationSource.POLICY,
        "url": None,
        "identifier": rule_path,
        "excerpt": (excerpt or "")[:100],
        "retrieved_at": _now_iso(),
        "confidence": "authoritative",
        "validated": True,
        "validation_method": "not_validated",
    }
    data["content_hash"] = _hash_citation(data)
    return data  # type: ignore[return-value]


def build_spdx_citation(license_id: str, spdx_entry: dict) -> Citation:
    data: dict[str, Any] = {
        "source": CitationSource.SPDX,
        "url": f"https://spdx.org/licenses/{license_id}.html",
        "identifier": license_id,
        "excerpt": (spdx_entry.get("name") or license_id)[:100],
        "retrieved_at": _now_iso(),
        "confidence": "authoritative",
        "validated": True,
        "validation_method": "api_response",
    }
    data["content_hash"] = _hash_citation(data)
    return data  # type: ignore[return-value]


def build_llm_inference_citation(reasoning: str) -> Citation:
    data: dict[str, Any] = {
        "source": CitationSource.LLM_INFERENCE,
        "url": None,  # ← intentionally None, always
        "identifier": None,
        "excerpt": (reasoning or "")[:100],
        "retrieved_at": _now_iso(),
        "confidence": "inferred",
        "validated": False,
        "validation_method": "not_validated",
    }
    data["content_hash"] = _hash_citation(data)
    return data  # type: ignore[return-value]


def build_curated_citation(package: str, mapping: dict) -> Citation:
    data: dict[str, Any] = {
        "source": CitationSource.CURATED_MAPPING,
        "url": None,
        "identifier": f"curated.{package}",
        "excerpt": (mapping.get("rationale") or "")[:100],
        "retrieved_at": _now_iso(),
        "confidence": "reliable",
        "validated": True,
        "validation_method": "not_validated",
    }
    data["content_hash"] = _hash_citation(data)
    return data  # type: ignore[return-value]


def build_none_found_citation(reason: str) -> Citation:
    data: dict[str, Any] = {
        "source": CitationSource.NONE_FOUND,
        "url": None,
        "identifier": None,
        "excerpt": (reason or "")[:100],
        "retrieved_at": _now_iso(),
        "confidence": "none",
        "validated": False,
        "validation_method": "none_found",
    }
    data["content_hash"] = _hash_citation(data)
    return data  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Remediation helpers
# ---------------------------------------------------------------------------

def _build_curated_swap(pkg: PackageRecord, mapping: dict, citation: Citation) -> Remediation:
    target = mapping.get("alternative") or "?"
    target_version = mapping.get("version")
    rem: dict[str, Any] = {
        "type": RemediationType.PACKAGE_SWAP,
        "description": (
            f"Replace {pkg['name']} with {target}"
            + (f"=={target_version}" if target_version else "")
        ),
        "target_package": target,
        "target_version": target_version,
        "confidence": "high",
        "rationale": mapping.get("rationale") or "Curated alternatives mapping.",
        "tradeoffs": mapping.get("tradeoffs"),
        "citations": [citation],
    }
    return rem  # type: ignore[return-value]


def _build_inference_swap_placeholder(pkg: PackageRecord, citation: Citation) -> Remediation:
    rem: dict[str, Any] = {
        "type": RemediationType.PACKAGE_SWAP,
        "description": f"Consider replacing {pkg['name']} (no curated alternative known).",
        "target_package": None,
        "target_version": None,
        "confidence": "low",
        "rationale": "No curated mapping available; manual identification required.",
        "tradeoffs": "Replacement package likely has API differences.",
        "citations": [citation],
    }
    return rem  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# LLM call (mockable in tests)
# ---------------------------------------------------------------------------

LLM_PROMPT_TEMPLATE = """You are a software license compliance analyst.

Here is the official SPDX license data for {license_spdx}:
{spdx_json}

The organization's declared use case is: {use_case}

Based ONLY on the SPDX data provided above, answer these questions:
1. Is this license compatible with the {use_case} use case? (yes/no/conditional)
2. What specific conditions apply, if any?
3. What is the compliance risk level? (critical/high/medium/low/none)
4. One sentence explanation.

Respond in JSON only:
{{
  "compatible": "yes|no|conditional",
  "conditions": "description or null",
  "risk_level": "critical|high|medium|low|none",
  "explanation": "one sentence"
}}

Do not reference any licenses, cases, or precedents not present in the
SPDX data above."""


async def _call_llm_for_license_reasoning(
    license_spdx: str, use_case: str, spdx_entry: dict
) -> dict:
    """
    Ask Claude to interpret the provided SPDX entry under the use_case.

    Returns the parsed JSON dict with keys: compatible, conditions,
    risk_level, explanation. Raises on SDK absence, network failure, or
    malformed output — caller catches and degrades to a defensive
    HUMAN_REVIEW Finding.

    anthropic is imported lazily so the module loads in environments that
    don't have it (tests mock this function entirely).
    """
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic()
    response = await client.messages.create(
        model=LLM_MODEL,
        max_tokens=512,
        messages=[
            {
                "role": "user",
                "content": LLM_PROMPT_TEMPLATE.format(
                    license_spdx=license_spdx,
                    spdx_json=json.dumps(spdx_entry, indent=2),
                    use_case=use_case,
                ),
            }
        ],
    )
    text = response.content[0].text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.rsplit("```", 1)[0]
    return json.loads(text)


# ---------------------------------------------------------------------------
# Finding factories
# ---------------------------------------------------------------------------

def _make_finding(
    pkg: PackageRecord,
    finding_type: str,
    severity: RiskLevel,
    description: str,
    recommendation: str,
    remediations: list[Remediation],
    citations: list[Citation],
    use_case: str,
    decision_status: DecisionStatus = DecisionStatus.PENDING,
) -> Finding:
    finding: dict[str, Any] = {
        "finding_id": f"f-{uuid.uuid4()}",
        "package": pkg["name"],
        "version": pkg["version"],
        "finding_type": finding_type,
        "severity": severity,
        "use_case": use_case,
        "description": description,
        "recommendation": recommendation,
        "remediations": remediations,
        "citations": citations,
        "decision_status": decision_status,
        "decision_rationale": None,
        "decided_at": None,
        "decided_by": None,
        "prior_decision": None,
    }
    return finding  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Per-package evaluation paths
# ---------------------------------------------------------------------------

def _evaluate_blocked(
    pkg: PackageRecord,
    license_id: str,
    use_case: str,
    spdx_dataset: dict,
    curated: dict,
) -> Finding:
    citations: list[Citation] = []
    spdx_entry = spdx_dataset.get(license_id)
    if spdx_entry:
        citations.append(build_spdx_citation(license_id, spdx_entry))
    # Citation identifier names the per-use_case path so auditors can
    # trace the exact policy rule that fired. The use_case prefix lets
    # a SaaS finding's audit row distinguish itself from a
    # distributed-binary finding for the same license — they're
    # generated by different rules under the new Design-1 schema.
    citations.append(
        build_policy_citation(
            f"policy.licenses.blocked.{use_case}[{license_id}]",
            f"{license_id} is in the organization's blocked license list "
            f"for use_case={use_case!r}.",
        )
    )

    remediations: list[Remediation] = []
    mapping = curated.get(pkg["name"]) or curated.get(pkg["name"].lower())
    if mapping:
        cit = build_curated_citation(pkg["name"], mapping)
        citations.append(cit)
        remediations.append(_build_curated_swap(pkg, mapping, cit))
        recommendation = (
            f"Replace {pkg['name']} with {mapping.get('alternative')}"
            + (f"=={mapping['version']}" if mapping.get("version") else "")
            + "."
        )
    else:
        cit = build_llm_inference_citation(
            f"No curated alternative known for {pkg['name']}; manual swap required."
        )
        citations.append(cit)
        remediations.append(_build_inference_swap_placeholder(pkg, cit))
        recommendation = f"Replace {pkg['name']} with a permissively licensed alternative."

    return _make_finding(
        pkg,
        finding_type="license_violation",
        severity=RiskLevel.CRITICAL,
        description=(
            f"{license_id} detected. Your declared use_case={use_case!r} "
            "blocks this license per organization policy "
            "(policy.licenses.blocked). Copyleft / distribution "
            "obligations under this license are likely to apply to your "
            "deployment model."
        ),
        recommendation=recommendation,
        remediations=remediations,
        citations=citations,
        use_case=use_case,
    )


def _evaluate_unknown(
    pkg: PackageRecord,
    use_case: str,
    unknown_action: str,
    extra_excerpt: str = "",
) -> Optional[Finding]:
    citations: list[Citation] = [
        build_none_found_citation(
            extra_excerpt or f"License metadata missing for {pkg['name']}."
        ),
        build_policy_citation(
            "policy.licenses.unknown_license_action",
            f"unknown_license_action = {unknown_action}",
        ),
    ]

    if unknown_action == "warn_and_continue":
        return None

    if unknown_action == "blocked":
        return _make_finding(
            pkg,
            finding_type="license_violation",
            severity=RiskLevel.CRITICAL,
            description=(
                f"License for {pkg['name']} is unknown and policy treats "
                "unknown licenses as violations."
            ),
            recommendation="Identify and verify the package's license.",
            remediations=[],
            citations=citations,
            use_case=use_case,
        )

    return _make_finding(
        pkg,
        finding_type="license_unknown",
        severity=RiskLevel.MEDIUM,
        description=(
            f"License for {pkg['name']} could not be determined. "
            "Manual review required."
        ),
        recommendation="Identify and verify the package's license.",
        remediations=[],
        citations=citations,
        use_case=use_case,
        decision_status=DecisionStatus.HUMAN_REVIEW,
    )


def _build_llm_finding(
    pkg: PackageRecord,
    license_id: str,
    spdx_entry: dict,
    reasoning: dict,
    use_case: str,
    counters: dict,
) -> Optional[Finding]:
    compatible = (reasoning.get("compatible") or "").strip().lower()
    risk_str = (reasoning.get("risk_level") or "").strip().lower()
    severity = RISK_LEVEL_FROM_STRING.get(risk_str, RiskLevel.MEDIUM)
    explanation = reasoning.get("explanation") or "LLM-derived assessment."

    # Two citations: SPDX (authoritative) + LLM_INFERENCE (inferred). NEVER one.
    citations: list[Citation] = [
        build_spdx_citation(license_id, spdx_entry),
        build_llm_inference_citation(explanation),
    ]

    if compatible == "yes":
        pkg["license_status"] = "compliant"
        return None  # compliant per LLM — no Finding

    if compatible == "no":
        finding_type = "license_violation"
        if severity == RiskLevel.NONE:
            severity = RiskLevel.HIGH
        counters["violations_found"] += 1
        pkg["license_status"] = "violation"
    else:
        finding_type = "license_restricted"
        if severity == RiskLevel.NONE:
            severity = RiskLevel.MEDIUM
        counters["restricted_found"] += 1
        pkg["license_status"] = "restricted"

    return _make_finding(
        pkg,
        finding_type=finding_type,
        severity=severity,
        description=f"{license_id}: {explanation}",
        recommendation=(
            reasoning.get("conditions")
            or "Review the license terms against the declared use case."
        ),
        remediations=[],
        citations=citations,
        use_case=use_case,
    )


def _blocked_for_use_case(licenses_cfg: dict, use_case: str) -> set[str]:
    """
    Return the set of SPDX license IDs blocked for `use_case` per the
    organization's policy.

    Supports two policy schemas:

    - **New schema (Design 1, 2026-05-18):** `licenses.blocked` is a dict
      keyed by use_case. Lookup is `blocked[use_case]`. A missing
      use_case key (or a None / non-list value) is treated as
      "nothing blocked for this use_case." This is the canonical
      shape in POLICY.yml and input_node.py SAFE_DEFAULTS.

    - **Legacy schema:** `licenses.blocked` is a flat list. Applied to
      EVERY use_case (preserves pre-Design-1 behavior for any policy
      override callers / fixtures that still pass the flat shape).
      Documented in BUGS.md "USE_CASE INVESTIGATION".

    isinstance dispatch is the cheapest robust signal — the YAML
    parser and JSON deserializers both produce dict for the new
    shape and list/tuple for the legacy shape. No magic string
    sentinels needed.
    """
    blocked_cfg = licenses_cfg.get("blocked")
    if isinstance(blocked_cfg, dict):
        per_case = blocked_cfg.get(use_case)
        return set(per_case or [])
    # Legacy flat-list compatibility — applies universally.
    return set(blocked_cfg or [])


async def _evaluate_license(
    pkg: PackageRecord,
    use_case: str,
    policy: dict,
    spdx_dataset: dict,
    curated: dict,
    counters: dict,
    errors: list[str],
) -> Optional[Finding]:
    license_id = pkg.get("license")
    licenses_cfg = policy.get("licenses") or {}
    allowed = set(licenses_cfg.get("allowed") or [])
    blocked = _blocked_for_use_case(licenses_cfg, use_case)
    unknown_action = licenses_cfg.get("unknown_license_action", "human_review")

    if not license_id:
        counters["unknown_found"] += 1
        pkg["license_status"] = "unknown"
        return _evaluate_unknown(pkg, use_case, unknown_action)

    # Stage 1: policy fast-path
    if license_id in allowed:
        pkg["license_status"] = "compliant"
        return None
    if license_id in blocked:
        counters["violations_found"] += 1
        pkg["license_status"] = "violation"
        return _evaluate_blocked(pkg, license_id, use_case, spdx_dataset, curated)

    # Stage 2: SPDX lookup
    spdx_entry = spdx_dataset.get(license_id)
    if not spdx_entry:
        counters["unknown_found"] += 1
        pkg["license_status"] = "unknown"
        return _evaluate_unknown(
            pkg,
            use_case,
            unknown_action,
            extra_excerpt=f"License {license_id!r} not found in SPDX dataset.",
        )

    # Stage 3: LLM reasoning (requires_review or unrecognized-but-real)
    counters["llm_calls_made"] += 1
    try:
        reasoning = await _call_llm_for_license_reasoning(
            license_id, use_case, spdx_entry
        )
    except Exception as exc:
        errors.append(
            f"LLM reasoning failed for {pkg['name']}=={pkg['version']} "
            f"({license_id}): {exc}"
        )
        # Defensive path: LLM failure means we couldn't classify the
        # license. Mark the package as "unknown" even though we emit a
        # restricted-finding to route this to human review.
        pkg["license_status"] = "unknown"
        return _make_finding(
            pkg,
            finding_type="license_restricted",
            severity=RiskLevel.MEDIUM,
            description=(
                f"License {license_id} requires review but LLM analysis "
                "failed; routed to human review."
            ),
            recommendation="Manually review this license against the use case.",
            remediations=[],
            citations=[
                build_spdx_citation(license_id, spdx_entry),
                build_none_found_citation(f"LLM call failed: {exc}"),
            ],
            use_case=use_case,
            decision_status=DecisionStatus.HUMAN_REVIEW,
        )

    # _build_llm_finding sets pkg["license_status"] based on LLM verdict.
    return _build_llm_finding(pkg, license_id, spdx_entry, reasoning, use_case, counters)


def _license_scan_complete_event(counters: dict, packages_scanned: int) -> dict:
    return {
        "timestamp": _now_iso(),
        "event_type": "license_scan_complete",
        "payload": {
            "packages_scanned": packages_scanned,
            "violations_found": counters["violations_found"],
            "restricted_found": counters["restricted_found"],
            "unknown_found": counters["unknown_found"],
            "llm_calls_made": counters["llm_calls_made"],
        },
    }


async def license_node(state: AgentState) -> dict:
    packages: list[PackageRecord] = list(state.get("packages") or [])
    use_case: str = state.get("use_case", "")
    policy: dict = state.get("policy") or {}

    spdx_dataset, spdx_warn = _load_spdx_dataset()
    curated, curated_warn = _load_curated_mappings()

    errors: list[str] = []
    if spdx_warn:
        errors.append(spdx_warn)
    if curated_warn:
        errors.append(curated_warn)

    counters = {
        "violations_found": 0,
        "restricted_found": 0,
        "unknown_found": 0,
        "llm_calls_made": 0,
    }

    if not packages:
        return {
            "license_findings": [],
            "audit_events": [_license_scan_complete_event(counters, 0)],
            "errors": errors,
        }

    sem = asyncio.Semaphore(LLM_CONCURRENCY)

    async def evaluate_with_sem(pkg: PackageRecord) -> Optional[Finding]:
        async with sem:
            return await _evaluate_license(
                pkg, use_case, policy, spdx_dataset, curated, counters, errors
            )

    results = await asyncio.gather(
        *(evaluate_with_sem(p) for p in packages),
        return_exceptions=True,
    )

    findings: list[Finding] = []
    for pkg, res in zip(packages, results):
        if isinstance(res, Exception):
            errors.append(
                f"unexpected error evaluating {pkg['name']}=={pkg['version']}: {res}"
            )
            continue
        if res is not None:
            findings.append(res)

    return {
        "license_findings": findings,
        # license_status was mutated in place on each PackageRecord above;
        # returning packages explicitly ensures LangGraph propagates the
        # update at fan-in (CVENode does not return packages, so there is
        # no parallel-write conflict).
        "packages": packages,
        "audit_events": [_license_scan_complete_event(counters, len(packages))],
        "errors": errors,
    }
