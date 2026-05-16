"""
smoke_test.py
=============
Quick integration sanity check. Run nodes in sequence against
demo_requirements.txt and print package/finding counts at each stage.

Not a unit test — this hits real subprocesses (pipdeptree, pip-licenses)
and (when uncommented) real APIs (OSV) and real LLM calls.

Usage:
    # 1. Activate a venv that has demo_requirements.txt installed
    source .demo-venv/bin/activate

    # 2. From repo root
    python smoke_test.py

Expected output on success:
    After Input:   status=running, errors=0
    After SBOM:    40+ packages
    After License: 3+ findings
    After CVE:     5+ findings

Known v1 limitation: SBOMNode reads the running venv, not demo_requirements.txt
directly. Packages that fail to install (e.g. mysqlclient on Mac without
MySQL libs) will be missing from the scan. Documented in errors[].
"""

import asyncio
import base64
import sys
from pathlib import Path

from nodes.input_node import input_node
from nodes.sbom_node import sbom_node
from nodes.license_node import license_node
from nodes.cve_node import cve_node


# Toggle these to skip API/LLM calls during fast iteration
RUN_LICENSE_NODE = True   # set False to skip LLM calls (no Anthropic key needed)
RUN_CVE_NODE = True       # set False to skip OSV API calls


async def smoke():
    # ------------------------------------------------------------------
    # 1. Load demo_requirements.txt as base64-encoded input
    # ------------------------------------------------------------------
    req_path = Path("demo_requirements.txt")
    if not req_path.exists():
        print(f"ERROR: {req_path} not found. Run from repo root.", file=sys.stderr)
        sys.exit(1)

    req_content = req_path.read_text()
    req_b64 = base64.b64encode(req_content.encode()).decode()

    # ------------------------------------------------------------------
    # 2. Build initial state — matches what api.py produces at /scan/start
    # ------------------------------------------------------------------
    state = {
        "job_id": "smoke-test-001",
        "input_type": "requirements_file",
        "input_value": req_b64,
        "use_case": "saas",
        "policy": {},
        "raw_dependency_tree": {},
        "packages": [],
        "license_findings": [],
        "cve_findings": [],
        "risk_matrix": [],
        "risk_summary": None,
        "pending_human_review": [],
        "resolved_findings": [],
        "audit_events": [],
        "audit_trail": [],
        "errors": [],
        "status": "running",
    }

    # ------------------------------------------------------------------
    # 3. Run nodes in sequence (skipping parallelism for smoke test)
    # ------------------------------------------------------------------
    print("=" * 60)
    print("SignedOff Smoke Test")
    print("=" * 60)

    # --- InputNode --------------------------------------------------
    result = await input_node(state)
    state.update(result)
    print(f"After Input:   status={state['status']}, "
          f"errors={len(state.get('errors', []))}, "
          f"policy_loaded={'policy' in state and bool(state['policy'])}")
    if state.get("status") == "failed":
        print("InputNode failed — aborting.")
        for err in state.get("errors", []):
            print(f"  - {err}")
        sys.exit(1)

    # --- SBOMNode ---------------------------------------------------
    result = await sbom_node(state)
    state.update(result)
    pkg_count = len(state.get("packages", []))
    direct = sum(1 for p in state["packages"] if not p.get("transitive"))
    transitive = pkg_count - direct
    cache_hits = sum(1 for p in state["packages"] if p.get("from_cache"))
    print(f"After SBOM:    {pkg_count} packages "
          f"({direct} direct, {transitive} transitive, "
          f"{cache_hits} from cache)")
    if pkg_count == 0:
        print("\n⚠️  No packages found. Likely causes:")
        print("   - Not running inside a venv with demo_requirements.txt installed")
        print("   - pipdeptree returned empty (check `pipdeptree --json-tree` manually)")
        print("   - Some packages failed to install (check errors[] below)")
        for err in state.get("errors", []):
            print(f"   - {err}")

    # --- LicenseNode ------------------------------------------------
    if RUN_LICENSE_NODE:
        try:
            result = await license_node(state)
            state.update(result)
            findings = state.get("license_findings", [])
            by_severity = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                sev_str = sev.value if hasattr(sev, "value") else str(sev)
                by_severity[sev_str] = by_severity.get(sev_str, 0) + 1
            print(f"After License: {len(findings)} findings  {by_severity}")
        except Exception as e:
            print(f"After License: ERROR — {type(e).__name__}: {e}")
    else:
        print("After License: SKIPPED (RUN_LICENSE_NODE=False)")

    # --- CVENode ----------------------------------------------------
    if RUN_CVE_NODE:
        try:
            result = await cve_node(state)
            state.update(result)
            findings = state.get("cve_findings", [])
            by_severity = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                sev_str = sev.value if hasattr(sev, "value") else str(sev)
                by_severity[sev_str] = by_severity.get(sev_str, 0) + 1
            print(f"After CVE:     {len(findings)} findings  {by_severity}")
        except Exception as e:
            print(f"After CVE:     ERROR — {type(e).__name__}: {e}")
    else:
        print("After CVE:     SKIPPED (RUN_CVE_NODE=False)")

    # ------------------------------------------------------------------
    # 4. Final summary
    # ------------------------------------------------------------------
    print("=" * 60)
    print(f"Audit events accumulated: {len(state.get('audit_events', []))}")
    print(f"Errors accumulated:       {len(state.get('errors', []))}")
    if state.get("errors"):
        print("\nErrors:")
        for err in state["errors"]:
            print(f"  - {err}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(smoke())
