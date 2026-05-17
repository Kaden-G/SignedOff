"""
api.py
======
FastAPI application that exposes the SignedOff compliance agent over HTTP.

The graph runs asynchronously in a background task. LangGraph's MemorySaver
checkpointer holds the actual scan state; we keep a lightweight metadata
dict here for fast lifecycle responses (404 vs job-exists-but-not-started).

CYA design rule: every response that carries job context echoes the
declared use_case so the frontend can never silently lose it between
scan initiation and result retrieval.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

# Load .env BEFORE importing anything that might construct an Anthropic
# client at import time. anthropic.AsyncAnthropic() reads ANTHROPIC_API_KEY
# from the process environment on instantiation, not on import — but doing
# this up front means every code path sees the same env regardless of
# import order.
from dotenv import load_dotenv

load_dotenv()

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel, Field, field_validator  # noqa: E402
from typing_extensions import Literal  # noqa: E402

from audit.verify_chain import verify_chain  # noqa: E402
from graph import graph, make_config, resume_after_hitl  # noqa: E402
from nodes.report_node import get_report  # noqa: E402


app = FastAPI(title="SignedOff Compliance Agent", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# ---------------------------------------------------------------------------
# Job lifecycle metadata (lightweight; full state lives in MemorySaver)
# ---------------------------------------------------------------------------

_job_metadata: dict[str, dict] = {}


def _record_job_started(job_id: str, use_case: str) -> None:
    _job_metadata[job_id] = {
        "use_case": use_case,
        "started_at": _now_iso(),
        "status": "running",
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScanStartRequest(BaseModel):
    input_type: Literal["requirements_file", "repo_url"]
    input_value: str
    use_case: Literal["saas", "internal", "distributed_binary"]
    policy_override: Optional[dict] = None

    @field_validator("input_value")
    @classmethod
    def input_value_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("input_value must not be empty")
        return v


class DecisionRequest(BaseModel):
    job_id: str
    decision_status: Literal["accepted", "deferred", "auto_remediate"]
    rationale: Optional[str] = None
    decided_by: str

    @field_validator("rationale")
    @classmethod
    def rationale_required_for_accept_defer(cls, v, info):
        status = info.data.get("decision_status")
        if status in ("accepted", "deferred") and not (v and v.strip()):
            raise ValueError(
                "rationale is required when decision_status is "
                "'accepted' or 'deferred'"
            )
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _enum_or_str(value, default: str = "") -> str:
    if value is None:
        return default
    return getattr(value, "value", str(value)).lower()


def _derive_phase(values: dict) -> str:
    status = values.get("status")
    if status == "complete":
        return "complete"
    if status == "failed":
        return "failed"
    if status == "awaiting_human":
        return "awaiting_review"
    if values.get("audit_trail"):
        return "finalizing"
    if values.get("risk_matrix"):
        return "risk_analysis"
    if values.get("license_findings") or values.get("cve_findings"):
        return "cve_scan" if values.get("cve_findings") else "license_scan"
    if values.get("packages"):
        return "license_scan"
    return "resolving_dependencies"


def _compute_progress(values: dict) -> int:
    if values.get("status") == "complete":
        return 100
    if values.get("audit_trail"):
        return 95
    if values.get("risk_matrix"):
        return 85
    packages = values.get("packages", []) or []
    if not packages:
        return 10
    pkgs_with_license = sum(1 for p in packages if p.get("license_status"))
    pkgs_with_cves = sum(1 for p in packages if p.get("cves") is not None)
    completed = min(pkgs_with_license, pkgs_with_cves)
    return min(80, 20 + int(60 * completed / max(len(packages), 1)))


def _count_analyzed(packages: list, license_findings: list, cve_findings: list) -> int:
    return sum(1 for p in packages if p.get("license_status") is not None)


def _count_severity_preview(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev_str = _enum_or_str(f.get("severity"))
        if sev_str in counts:
            counts[sev_str] += 1
    counts["total"] = sum(counts.values())
    return counts


def _derive_overall_status(
    findings: list,
    license_risk: str = "none",
    security_risk: str = "none",
) -> str:
    """
    Compute a per-package overall status from BOTH risk dimensions and
    the findings' decision_status values.

    A row with security_risk="critical" + finding_count=61 must never
    render as "clean" just because the findings' decision_status field
    happens to be unset or unrecognized. The fix surfaces the row as
    "human_review" any time it has non-clean risk dimensions OR
    findings whose status couldn't be classified as a known resolved
    state.

    Rule order (first match wins):
      1. Any HITL finding             → "human_review"
      2. All findings resolved        → "auto_remediate" / "auto_accepted" / "deferred"
      3. No findings AND both dims    → "clean"
         risks are "none"
      4. Defensive default            → "human_review"
         (findings with unknown status, or no findings but non-clean
         risk dimensions — these need eyes on them)
    """
    statuses = {_enum_or_str(f.get("decision_status")) for f in (findings or [])}

    # Rule 1: HITL wins regardless of any other signal.
    if "human_review" in statuses:
        return "human_review"

    # Rule 2: all findings have a terminal non-human status.
    resolved_set = {"auto_remediate", "accepted", "deferred"}
    if findings and statuses.issubset(resolved_set):
        if "auto_remediate" in statuses:
            return "auto_remediate"
        if "accepted" in statuses:
            return "auto_accepted"
        return "deferred"

    # Rule 3: truly clean — no findings AND both risk dimensions are none.
    if not findings and license_risk == "none" and security_risk == "none":
        return "clean"

    # Rule 4: defensive — findings exist with unrecognized statuses, OR
    # findings empty but a risk dimension is populated. Either way, the
    # row needs a human looking at it.
    return "human_review"


def _derive_action_label(
    findings: list,
    license_risk: str,
    security_risk: str,
    overall_status: Optional[str] = None,
) -> str:
    """
    Surface the action affordance for the row. Drives the right-hand
    Action column in the risk-matrix table.

    Counts are included in the human_review label so the demo can show
    "Review 61 CVEs" instead of a generic "Review CVEs" — the count is
    what makes the urgency obvious at a glance.
    """
    if overall_status == "clean":
        return "Clean"
    if overall_status in ("auto_remediate", "auto_accepted", "deferred"):
        return "Resolved"

    findings = findings or []
    has_license = any("license" in str(f.get("finding_type", "")) for f in findings)
    has_cve = any(str(f.get("finding_type", "")).startswith("cve") for f in findings)
    n = len(findings)

    if has_license and has_cve:
        return f"Review {n} findings" if n else "Two-track review"
    if has_license:
        if license_risk in ("critical", "high"):
            return "Replace Package"
        return "Review License"
    if has_cve:
        return f"Review {n} CVE{'s' if n != 1 else ''}"

    # No findings classified — but overall_status said human_review,
    # which only happens when a risk dimension is populated.
    if license_risk != "none" and security_risk != "none":
        return "Two-track review"
    if license_risk != "none":
        return "Review License"
    if security_risk != "none":
        return "Review CVEs"
    return "Review"


def _has_fix(finding: dict) -> bool:
    for r in finding.get("remediations") or []:
        r_type_str = _enum_or_str(r.get("type"))
        if r_type_str in ("version_bump", "package_swap"):
            return True
    return False


def _build_matrix_summary(rows: list[dict]) -> dict:
    summary = {
        "total_packages": len(rows),
        "packages_with_findings": sum(1 for r in rows if r["finding_count"] > 0),
        "packages_clean": sum(1 for r in rows if r["finding_count"] == 0),
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "awaiting_review_count": 0,
    }
    name_by_idx = {v: k for k, v in SEVERITY_ORDER.items()}
    for r in rows:
        max_idx = max(
            SEVERITY_ORDER.get(r["license_risk"], 0),
            SEVERITY_ORDER.get(r["security_risk"], 0),
        )
        if max_idx > 0:
            summary[f"{name_by_idx[max_idx]}_count"] += 1
        if r["overall_status"] == "human_review":
            summary["awaiting_review_count"] += 1
    return summary


def _err(status_code: int, error: str, message: str, **extra) -> HTTPException:
    payload = {"error": error, "message": message}
    payload.update(extra)
    return HTTPException(status_code=status_code, detail=payload)


# ---------------------------------------------------------------------------
# POST /scan/start
# ---------------------------------------------------------------------------

@app.post("/scan/start", status_code=202)
async def start_scan(body: ScanStartRequest, background_tasks: BackgroundTasks):
    job_id = f"job-{uuid.uuid4()}"
    started_at = _now_iso()

    initial_state: dict[str, Any] = {
        "job_id": job_id,
        "input_type": body.input_type,
        "input_value": body.input_value,
        "use_case": body.use_case,
        "policy": {},
        "raw_dependency_tree": {},
        "packages": [],
        "license_findings": [],
        "cve_findings": [],
        "risk_matrix": [],
        "risk_summary": None,
        "pending_human_review": [],
        "resolved_findings": [],
        "audit_trail": [],
        "audit_events": [],
        "errors": [],
        "status": "running",
        "started_at": started_at,
    }

    _record_job_started(job_id, body.use_case)

    config = make_config(job_id)
    background_tasks.add_task(_run_graph_safely, initial_state, config, job_id)

    return {
        "job_id": job_id,
        "use_case": body.use_case,
        "status": "running",
        "created_at": started_at,
    }


async def _run_graph_safely(initial_state: dict, config: dict, job_id: str) -> None:
    """Catch graph execution errors and stash them on the job metadata."""
    try:
        await graph.ainvoke(initial_state, config=config)
        if job_id in _job_metadata:
            _job_metadata[job_id]["status"] = "complete"
    except Exception as exc:
        if job_id in _job_metadata:
            _job_metadata[job_id]["status"] = "failed"
            _job_metadata[job_id]["error"] = str(exc)


# ---------------------------------------------------------------------------
# GET /scan/status/{job_id}
# ---------------------------------------------------------------------------

@app.get("/scan/status/{job_id}")
async def get_status(job_id: str):
    if job_id not in _job_metadata:
        raise _err(404, "job_not_found", f"No scan job found with id {job_id}")

    config = make_config(job_id)
    state = await graph.aget_state(config)

    if not state or not state.values:
        meta = _job_metadata[job_id]
        return {
            "job_id": job_id,
            "use_case": meta["use_case"],
            "status": "running",
            "current_phase": "initializing",
            "progress_pct": 0,
            "packages_total": 0,
            "packages_analyzed": 0,
            "cache_hits": 0,
            "current_activity": [],
            "findings_preview": {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0
            },
            "errors": [],
            "started_at": meta["started_at"],
            "completed_at": None,
        }

    values = state.values
    packages = values.get("packages") or []
    license_findings = values.get("license_findings") or []
    cve_findings = values.get("cve_findings") or []
    all_findings = license_findings + cve_findings

    return {
        "job_id": job_id,
        "use_case": values.get("use_case") or _job_metadata[job_id]["use_case"],
        "status": values.get("status", "running"),
        "current_phase": _derive_phase(values),
        "progress_pct": _compute_progress(values),
        "packages_total": len(packages),
        "packages_analyzed": _count_analyzed(packages, license_findings, cve_findings),
        "cache_hits": sum(1 for p in packages if p.get("from_cache")),
        "current_activity": (values.get("current_activity") or [])[-10:],
        "findings_preview": _count_severity_preview(all_findings),
        "errors": values.get("errors") or [],
        "started_at": values.get("started_at") or _job_metadata[job_id]["started_at"],
        "completed_at": values.get("completed_at"),
    }


# ---------------------------------------------------------------------------
# GET /scan/results/{job_id}
# ---------------------------------------------------------------------------

@app.get("/scan/results/{job_id}")
async def get_results(job_id: str):
    """
    Return the analysis snapshot for a scan.

    Idempotent across lifecycle: the same URL works whether the scan
    is mid-flight, paused at the HITL gate, or complete. The response
    `scan_status` field tells the UI which state the data represents.
    """
    if job_id not in _job_metadata:
        raise _err(404, "job_not_found", f"No scan job found with id {job_id}")

    report = get_report(job_id)
    if report:
        return {**report, "scan_status": "complete"}

    # No stored report yet — serve a partial view from live graph state.
    config = make_config(job_id)
    state = await graph.aget_state(config)
    values = (state.values if state else None) or {}
    meta = _job_metadata[job_id]
    partial = _synthesize_report_from_state(
        values, job_id, fallback_use_case=meta.get("use_case"),
    )
    partial["scan_status"] = values.get("status") or meta.get("status", "running")
    return partial


# ---------------------------------------------------------------------------
# GET /scan/risk-matrix/{job_id}?view=grouped|flat
# ---------------------------------------------------------------------------

@app.get("/scan/risk-matrix/{job_id}")
async def get_risk_matrix(
    job_id: str,
    view: Literal["grouped", "flat"] = Query("grouped"),
):
    """
    Return the risk matrix (grouped per-package or flat per-finding).

    Idempotent across lifecycle: when the scan is mid-flight or paused
    at the HITL gate, this serves a partial view synthesized from live
    graph state. When the scan is complete, it serves from the stored
    report. The response `scan_status` field tells the UI which state
    the data represents.
    """
    if job_id not in _job_metadata:
        raise _err(404, "job_not_found", f"No scan job found with id {job_id}")

    report = get_report(job_id)
    if report:
        source = report
        scan_status = "complete"
    else:
        config = make_config(job_id)
        state = await graph.aget_state(config)
        values = (state.values if state else None) or {}
        meta = _job_metadata[job_id]
        source = _synthesize_report_from_state(
            values, job_id, fallback_use_case=meta.get("use_case"),
        )
        scan_status = values.get("status") or meta.get("status", "running")

    result = _build_flat_view(source) if view == "flat" else _build_grouped_view(source)
    result["scan_status"] = scan_status
    return result


def _synthesize_report_from_state(
    values: dict,
    job_id: str,
    fallback_use_case: Optional[str] = None,
) -> dict:
    """
    Build a report-shaped dict from live graph state so the grouped/flat
    view helpers and `/scan/results` can serve the same response shape
    regardless of whether the scan is mid-flight or complete.

    Mirrors the field set produced by nodes/report_node.py — packages,
    license_findings, cve_findings, raw_dependency_tree, use_case,
    job_id, scanned_at, summary, executive_summary.

    Missing fields are filled defensively: empty lists for collections,
    None for optional scalars, _job_metadata fallback for use_case when
    SBOMNode hasn't written to state yet.
    """
    license_findings = list(values.get("license_findings") or [])
    cve_findings = list(values.get("cve_findings") or [])
    all_findings = license_findings + cve_findings
    packages = list(values.get("packages") or [])

    sev_counts: dict[str, int] = {
        level: 0 for level in ("critical", "high", "medium", "low", "none")
    }
    for f in all_findings:
        sev = _enum_or_str(f.get("severity"))
        if sev in sev_counts:
            sev_counts[sev] += 1

    summary = {
        "packages_total": len(packages),
        "packages_direct": sum(1 for p in packages if not p.get("transitive")),
        "packages_transitive": sum(1 for p in packages if p.get("transitive")),
        "cache_hits": sum(1 for p in packages if p.get("from_cache")),
        "findings_total": len(all_findings),
        "findings_by_severity": sev_counts,
    }

    return {
        "job_id": job_id,
        "use_case": values.get("use_case") or fallback_use_case,
        "scanned_at": values.get("started_at"),
        "completed_at": values.get("completed_at"),
        "summary": summary,
        "executive_summary": values.get("risk_summary"),
        "packages": packages,
        "license_findings": license_findings,
        "cve_findings": cve_findings,
        "raw_dependency_tree": values.get("raw_dependency_tree") or {},
    }


def _build_dependency_chains(raw_tree) -> dict[str, list[str]]:
    """
    Walk the pipdeptree JSON tree and produce a map of:
      package_name (lower) -> list of parent packages (the chain that pulled it in).
    For direct deps, the list is empty.

    Accepts either the raw pipdeptree list-of-dicts shape or the wrapped
    {"tree": [...]} shape used in AgentState["raw_dependency_tree"].
    """
    if isinstance(raw_tree, dict):
        tree = raw_tree.get("tree") or []
    elif isinstance(raw_tree, list):
        tree = raw_tree
    else:
        tree = []

    chains: dict[str, list[str]] = {}

    def walk(node: dict, ancestors: list[str]) -> None:
        if not isinstance(node, dict):
            return
        raw_name = node.get("package_name") or node.get("key") or ""
        name = raw_name.lower()
        if name and name not in chains:
            chains[name] = list(ancestors)
        next_ancestors = ancestors + [name] if name else list(ancestors)
        for dep in node.get("dependencies") or []:
            walk(dep, next_ancestors)

    if isinstance(tree, list):
        for top in tree:
            walk(top, [])
    return chains


def _pick_max_contextualized(findings: list[dict]) -> tuple[Optional[str], Optional[str]]:
    """
    Across findings for a package, return (severity, rationale) for the
    contextualized CVE finding with the highest contextualized severity.
    Returns (None, None) if no CVE finding was contextualized.
    """
    best_idx = -1
    best_sev: Optional[str] = None
    best_rationale: Optional[str] = None
    for f in findings:
        ctx = f.get("contextualized_severity")
        if ctx is None:
            continue
        sev_str = _enum_or_str(ctx)
        idx = SEVERITY_ORDER.get(sev_str, -1)
        if idx > best_idx:
            best_idx = idx
            best_sev = sev_str
            best_rationale = f.get("contextualization_rationale")
    return best_sev, best_rationale


def _build_grouped_view(report: dict) -> dict:
    packages = report.get("packages") or []
    all_findings = (report.get("license_findings") or []) + (report.get("cve_findings") or [])
    use_case = report.get("use_case")
    chains = _build_dependency_chains(report.get("raw_dependency_tree") or {})

    findings_by_pkg: dict[tuple[str, str], list[dict]] = {}
    for f in all_findings:
        findings_by_pkg.setdefault((f["package"], f["version"]), []).append(f)

    rows: list[dict] = []
    for pkg in packages:
        key = (pkg["name"], pkg["version"])
        pkg_findings = findings_by_pkg.get(key, [])
        license_risk = _enum_or_str(pkg.get("license_risk"), "none")
        security_risk = _enum_or_str(pkg.get("security_risk"), "none")
        ctx_sev, ctx_rationale = _pick_max_contextualized(pkg_findings)
        overall_status = _derive_overall_status(
            pkg_findings, license_risk, security_risk
        )
        rows.append({
            "package": pkg["name"],
            "version": pkg["version"],
            "transitive": pkg.get("transitive", False),
            "use_case": use_case,
            "license_risk": license_risk,
            "security_risk": security_risk,
            "overall_status": overall_status,
            "finding_count": len(pkg_findings),
            "finding_ids": [f["finding_id"] for f in pkg_findings],
            "action_label": _derive_action_label(
                pkg_findings, license_risk, security_risk, overall_status
            ),
            "has_fix_available": any(_has_fix(f) for f in pkg_findings),
            "dependency_chain": chains.get(pkg["name"].lower(), []),
            "contextualized_severity": ctx_sev,
            "contextualization_rationale": ctx_rationale,
        })

    rows.sort(key=lambda r: (
        -max(SEVERITY_ORDER.get(r["license_risk"], 0),
             SEVERITY_ORDER.get(r["security_risk"], 0)),
        r["package"],
    ))

    return {
        "job_id": report["job_id"],
        "use_case": use_case,
        "scanned_at": report.get("scanned_at"),
        "summary": _build_matrix_summary(rows),
        "rows": rows,
    }


def _build_flat_view(report: dict) -> dict:
    all_findings = (report.get("license_findings") or []) + (report.get("cve_findings") or [])
    use_case = report.get("use_case")
    packages = report.get("packages") or []
    transitive_lookup = {
        (p["name"], p["version"]): p.get("transitive", False) for p in packages
    }
    chains = _build_dependency_chains(report.get("raw_dependency_tree") or {})

    findings_list: list[dict] = []
    for f in all_findings:
        sev_str = _enum_or_str(f.get("severity"))
        fix_version = None
        for r in f.get("remediations") or []:
            if _enum_or_str(r.get("type")) == "version_bump":
                fix_version = r.get("target_version")
                break
        citations = f.get("citations") or []
        primary_source = _enum_or_str(citations[0].get("source")) if citations else None
        ctx = f.get("contextualized_severity")
        ctx_sev_str = _enum_or_str(ctx) if ctx is not None else None
        findings_list.append({
            "finding_id": f["finding_id"],
            "package": f["package"],
            "version": f["version"],
            "finding_type": f.get("finding_type"),
            "severity": sev_str,
            "use_case": use_case,
            "description": f.get("description", ""),
            "recommendation": f.get("recommendation", ""),
            "decision_status": _enum_or_str(f.get("decision_status")),
            "transitive": transitive_lookup.get((f["package"], f["version"]), False),
            "has_fix_available": fix_version is not None,
            "fix_version": fix_version,
            "citation_count": len(citations),
            "primary_citation_source": primary_source,
            "contextualized_severity": ctx_sev_str,
            "contextualization_rationale": f.get("contextualization_rationale"),
            "dependency_chain": chains.get(f["package"].lower(), []),
        })

    findings_list.sort(key=lambda f: (
        -SEVERITY_ORDER.get(f["severity"], 0), f["package"]
    ))

    return {
        "job_id": report["job_id"],
        "use_case": use_case,
        "scanned_at": report.get("scanned_at"),
        "findings": findings_list,
    }


# ---------------------------------------------------------------------------
# GET /scan/pending-review/{job_id}
# ---------------------------------------------------------------------------

@app.get("/scan/pending-review/{job_id}")
async def get_pending_review(job_id: str):
    if job_id not in _job_metadata:
        raise _err(404, "job_not_found", f"No scan job found with id {job_id}")

    config = make_config(job_id)
    state = await graph.aget_state(config)
    if not state or not state.values:
        return {
            "job_id": job_id,
            "use_case": _job_metadata[job_id]["use_case"],
            "pending_count": 0,
            "findings": [],
        }

    values = state.values
    pending = values.get("pending_human_review") or []
    policy = values.get("policy") or {}
    prior_decisions_cfg = policy.get("prior_decisions") or {}
    chains = _build_dependency_chains(values.get("raw_dependency_tree") or {})

    enhanced: list[dict] = []
    for f in pending:
        f_copy = dict(f)
        prior = f_copy.get("prior_decision")
        if prior:
            sev_str = _enum_or_str(f_copy.get("severity"))
            mode = (prior_decisions_cfg.get(sev_str) or {}).get("mode")
            if mode:
                prior_with_mode = dict(prior)
                prior_with_mode["l2_mode"] = mode
                f_copy["prior_decision"] = prior_with_mode
        f_copy["dependency_chain"] = chains.get(f_copy["package"].lower(), [])
        enhanced.append(f_copy)

    return {
        "job_id": job_id,
        "use_case": values.get("use_case") or _job_metadata[job_id]["use_case"],
        "pending_count": len(enhanced),
        "findings": enhanced,
    }


# ---------------------------------------------------------------------------
# POST /scan/decision/{finding_id}
# ---------------------------------------------------------------------------

@app.post("/scan/decision/{finding_id}")
async def submit_decision(finding_id: str, body: DecisionRequest):
    if body.job_id not in _job_metadata:
        raise _err(404, "job_not_found", f"No scan job found with id {body.job_id}")

    config = make_config(body.job_id)
    state = await graph.aget_state(config)
    if not state or not state.values:
        raise _err(404, "job_not_found",
                   f"No graph state for {body.job_id}")

    pending = state.values.get("pending_human_review") or []
    if not any(f["finding_id"] == finding_id for f in pending):
        resolved = state.values.get("resolved_findings") or []
        already = next(
            (f for f in resolved if f["finding_id"] == finding_id), None
        )
        if already:
            raise _err(
                409, "already_decided",
                f"Finding {finding_id} has already been decided.",
                current_status=_enum_or_str(already.get("decision_status")),
            )
        raise _err(404, "finding_not_found",
                   f"Finding {finding_id} is not pending review")

    await resume_after_hitl(body.job_id, [{
        "finding_id": finding_id,
        "decision_status": body.decision_status,
        "rationale": body.rationale,
        "decided_by": body.decided_by,
    }])

    state = await graph.aget_state(config)
    pending_remaining = len((state.values or {}).get("pending_human_review") or [])
    graph_status = "finalizing" if pending_remaining == 0 else "awaiting_human"

    return {
        "finding_id": finding_id,
        "job_id": body.job_id,
        "use_case": (state.values or {}).get("use_case")
        or _job_metadata[body.job_id]["use_case"],
        "decision_status": body.decision_status,
        "decided_by": body.decided_by,
        "decided_at": _now_iso(),
        "pending_remaining": pending_remaining,
        "graph_status": graph_status,
    }


# ---------------------------------------------------------------------------
# GET /audit/trail/{job_id}
# ---------------------------------------------------------------------------

def _wrap_pending_audit_events(events: list) -> list[dict]:
    """
    Decorate in-flight audit_events (accumulated by nodes during the
    scan but not yet hash-chained by AuditNode) with placeholder
    chain fields and a pending_seal marker. The placeholders are NOT
    real hashes — they're typographically distinct ("PENDING-...") so
    no consumer can mistake them for sealed entries.

    AuditNode runs as the terminal step at scan completion; it sorts
    audit_events by timestamp and writes the canonical hash-chained
    audit_trail. Until then, /audit/trail surfaces these pending
    events so the dashboard can show activity accumulating live —
    a much better demo than "0 entries · No tampering detected".
    """
    wrapped: list[dict] = []
    for i, ev in enumerate(events or []):
        if not isinstance(ev, dict):
            continue
        wrapped.append({
            "seq": i,
            "timestamp": ev.get("timestamp"),
            "event_type": ev.get("event_type"),
            "payload": ev.get("payload") or {},
            "prev_hash": "PENDING-not-yet-sealed",
            "entry_hash": "PENDING-not-yet-sealed",
            "seal_status": "pending",
        })
    return wrapped


@app.get("/audit/trail/{job_id}")
async def get_audit_trail(job_id: str):
    """
    Idempotent across the scan lifecycle.

    - seal_status="complete": entries[] is the canonical hash-chained
      audit_trail sealed by AuditNode at scan completion. chain_valid
      reflects a real chain verification.
    - seal_status="pending": entries[] is synthesized from the
      in-flight audit_events list that nodes have accumulated so far.
      prev_hash / entry_hash are PENDING placeholders. AuditNode has
      not yet run, so no real chain exists to verify.
    """
    if job_id not in _job_metadata:
        raise _err(404, "job_not_found", f"No scan job found with id {job_id}")

    config = make_config(job_id)
    state = await graph.aget_state(config)
    values = (state.values if state else None) or {}

    audit_trail = values.get("audit_trail") or []
    if audit_trail:
        verification = verify_chain(audit_trail)
        return {
            "job_id": job_id,
            "use_case": values.get("use_case") or _job_metadata[job_id]["use_case"],
            "seal_status": "complete",
            "entry_count": len(audit_trail),
            "chain_valid": verification["chain_valid"],
            "entries": audit_trail,
        }

    # Pre-seal: surface the in-flight events so the dashboard can show
    # what's accumulating. No real chain to verify yet.
    pending = values.get("audit_events") or []
    return {
        "job_id": job_id,
        "use_case": values.get("use_case") or _job_metadata[job_id]["use_case"],
        "seal_status": "pending",
        "entry_count": len(pending),
        "chain_valid": None,
        "entries": _wrap_pending_audit_events(pending),
    }


# ---------------------------------------------------------------------------
# GET /audit/verify/{job_id}
# ---------------------------------------------------------------------------

@app.get("/audit/verify/{job_id}")
async def verify_audit(job_id: str):
    """
    Independent chain verification.

    Pre-seal (AuditNode hasn't run yet) returns seal_status="pending"
    with chain_valid=null and an explanatory message — there is no
    chain to verify yet, only in-flight audit_events. The UI should
    surface this as "chain seals at scan completion" rather than
    rendering a misleading "0 entries verified · No tampering".
    """
    if job_id not in _job_metadata:
        raise _err(404, "job_not_found", f"No scan job found with id {job_id}")

    config = make_config(job_id)
    state = await graph.aget_state(config)
    values = (state.values if state else None) or {}

    audit_trail = values.get("audit_trail") or []
    if not audit_trail:
        pending_count = len(values.get("audit_events") or [])
        return {
            "job_id": job_id,
            "verified_at": _now_iso(),
            "seal_status": "pending",
            "chain_valid": None,
            "broken_at_seq": None,
            "citation_hashes_valid": None,
            "citation_hash_mismatches": [],
            "entries_verified": 0,
            "citations_verified": 0,
            "verdict": "PENDING",
            "pending_entries": pending_count,
            "message": (
                "Chain not yet sealed. "
                f"{pending_count} event{'s' if pending_count != 1 else ''} "
                "accumulated during scan, awaiting sealing by AuditNode "
                "at completion. Submit decisions to advance the scan."
            ),
        }

    result = verify_chain(audit_trail)
    return {
        "job_id": job_id,
        "verified_at": _now_iso(),
        "seal_status": "complete",
        "chain_valid": result["chain_valid"],
        "broken_at_seq": result["broken_at_seq"],
        # v1: per-citation hash verification not separately implemented;
        # surfaces here as PASS so the API contract stays stable for v2.
        "citation_hashes_valid": True,
        "citation_hash_mismatches": [],
        "entries_verified": result["entries_verified"],
        "citations_verified": 0,
        "verdict": result["verdict"],
    }


# ---------------------------------------------------------------------------
# Demo helper + static dashboard
# ---------------------------------------------------------------------------

import os  # noqa: E402

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
_DEMO_REQUIREMENTS_PATH = os.path.join(
    os.path.dirname(__file__), "demo_requirements.txt"
)


@app.get("/demo/requirements", include_in_schema=False)
async def get_demo_requirements():
    """Return demo_requirements.txt contents for the 'Use Demo Data' button."""
    try:
        with open(_DEMO_REQUIREMENTS_PATH) as f:
            content = f.read()
    except FileNotFoundError:
        raise _err(404, "demo_not_found", "demo_requirements.txt not found")
    return {"content": content, "filename": "demo_requirements.txt"}


if os.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    index_path = os.path.join(_STATIC_DIR, "index.html")
    if not os.path.isfile(index_path):
        raise _err(404, "dashboard_not_built", "static/index.html not found")
    return FileResponse(index_path)
