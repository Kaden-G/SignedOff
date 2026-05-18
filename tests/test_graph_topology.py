"""
Tests for the LangGraph topology in graph.py.

The focus here is on the JOIN semantics at risk_node — without
`defer=True` on the risk_node registration, the Pregel runtime could
schedule risk_node as soon as license_node finished, populate
pending_human_review from license findings alone, flip status to
"awaiting_human", and trigger the HITL interrupt before cve_node
completed. The result observed in integration was a partial risk
matrix served to the API (license-only, security_risk=NONE on every
package).

We exercise the actual topology in graph.py — same node names, same
edges, same router functions — but swap in tiny stub node functions
that:
  - simulate license_node finishing instantly
  - simulate cve_node taking long enough that, without a barrier,
    LangGraph would advance to risk_node + decision_gate before cve
    completes
  - mark risk_node so we can count how many times it ran and what
    findings it saw on each run
"""

from __future__ import annotations

import asyncio
import operator
import sys
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import interrupt

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph import (  # noqa: E402
    route_after_input,
    route_after_risk,
    route_after_sbom,
    route_to_audit,
)


# ---------------------------------------------------------------------------
# Minimal state schema matching the real fields the routers read.
# We keep this local so the test doesn't depend on the full AgentState
# (which carries 20+ fields irrelevant to the join question).
# ---------------------------------------------------------------------------

class _TopoState(TypedDict, total=False):
    license_findings:    Annotated[list, operator.add]
    cve_findings:        Annotated[list, operator.add]
    risk_matrix:         list
    pending_human_review: list
    resolved_findings:   Annotated[list, operator.add]
    audit_events:        Annotated[list, operator.add]
    risk_runs:           Annotated[list, operator.add]
    status:              str
    packages:            list


# ---------------------------------------------------------------------------
# Stub nodes — same names + same routing contract as the real ones.
# ---------------------------------------------------------------------------

async def _stub_input(state):
    return {"status": "running"}


async def _stub_sbom(state):
    return {"packages": [{"name": "pkg-a"}], "status": "running"}


async def _stub_license(state):
    # Finishes essentially instantly. The race condition is exposed by
    # the fact that license is fast while cve is slow.
    return {"license_findings": [{"sev": "high", "type": "license_violation"}]}


async def _stub_cve_slow(state, *, delay_seconds: float):
    await asyncio.sleep(delay_seconds)
    return {"cve_findings": [{"sev": "critical", "type": "cve"}]}


async def _stub_risk(state):
    """Mimics real risk_node: merges both branches, populates buckets.

    Records what it saw on each invocation in `risk_runs` so the test
    can detect whether the join held (single run with both branches) or
    broke (first run sees only license, then a later run sees both).
    """
    lic = list(state.get("license_findings") or [])
    cve = list(state.get("cve_findings") or [])
    all_findings = lic + cve
    pending = [f for f in all_findings if f.get("sev") in ("high", "critical")]
    return {
        "risk_matrix": all_findings,
        "pending_human_review": pending,
        "resolved_findings": [],
        "risk_runs": [{"lic": len(lic), "cve": len(cve)}],
        "status": "awaiting_human" if pending else "running",
    }


async def _stub_decision_gate(state):
    if state.get("pending_human_review"):
        interrupt({"reason": "stub_gate"})
    return {}


async def _stub_auto_remediate(state):
    return {}


async def _stub_auto_accept(state):
    return {}


async def _stub_audit(state):
    return {"audit_events": [{"event_type": "audit_stub"}]}


async def _stub_report(state):
    return {}


# ---------------------------------------------------------------------------
# Topology builder mirroring graph.py exactly — same routers, same edges,
# same node names. The only thing that changes between tests is whether
# risk_node is registered with defer=True.
# ---------------------------------------------------------------------------

def _build_topology(
    *,
    cve_delay: float = 0.4,
    defer_risk: bool = True,
):
    builder = StateGraph(_TopoState)
    builder.add_node("input_node",          _stub_input)
    builder.add_node("sbom_node",           _stub_sbom)
    builder.add_node("license_node",        _stub_license)

    async def _cve(state):
        return await _stub_cve_slow(state, delay_seconds=cve_delay)
    builder.add_node("cve_node",            _cve)

    # The setting under test.
    if defer_risk:
        builder.add_node("risk_node",       _stub_risk, defer=True)
    else:
        builder.add_node("risk_node",       _stub_risk)

    builder.add_node("decision_gate_node",  _stub_decision_gate)
    builder.add_node("auto_remediate_node", _stub_auto_remediate)
    builder.add_node("auto_accept_node",    _stub_auto_accept)
    builder.add_node("audit_node",          _stub_audit)
    builder.add_node("report_node",         _stub_report)

    builder.set_entry_point("input_node")
    builder.add_conditional_edges("input_node", route_after_input)
    builder.add_conditional_edges("sbom_node",  route_after_sbom)
    builder.add_edge("license_node", "risk_node")
    builder.add_edge("cve_node",     "risk_node")
    builder.add_conditional_edges("risk_node",          route_after_risk)
    builder.add_conditional_edges("decision_gate_node", route_to_audit)
    builder.add_edge("auto_remediate_node", "audit_node")
    builder.add_edge("auto_accept_node",    "audit_node")
    builder.add_edge("audit_node",  "report_node")
    builder.add_edge("report_node", END)

    return builder.compile(checkpointer=MemorySaver())


def _initial_state() -> dict:
    return {
        "license_findings": [], "cve_findings": [], "risk_matrix": [],
        "pending_human_review": [], "resolved_findings": [],
        "audit_events": [], "risk_runs": [], "packages": [],
        "status": "running",
    }


def _run_until_pause(g, thread_id: str) -> dict:
    cfg = {"configurable": {"thread_id": thread_id}}
    async def _go():
        try:
            await g.ainvoke(_initial_state(), config=cfg)
        except Exception:
            # interrupt() may surface as an exception in some langgraph
            # builds; the post-pause state is what we care about.
            pass
        snap = await g.aget_state(cfg)
        return snap.values
    return asyncio.run(_go())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_risk_node_runs_after_both_branches_complete():
    """
    Regression: risk_node must see BOTH license_findings and cve_findings
    populated. With defer=True on risk_node, the Pregel runtime waits
    until cve_node completes before invoking risk_node, even though
    license_node finishes first.
    """
    g = _build_topology(cve_delay=0.3, defer_risk=True)
    values = _run_until_pause(g, "topo-defer")

    assert len(values["license_findings"]) == 1
    assert len(values["cve_findings"]) == 1, (
        f"cve_findings empty at pause — join broke: {values}"
    )
    # risk_matrix carries BOTH branches.
    types = {f["type"] for f in values["risk_matrix"]}
    assert types == {"license_violation", "cve"}, (
        f"risk_matrix is partial: {values['risk_matrix']}"
    )


def test_risk_node_runs_exactly_once_with_full_state():
    """
    The merge is committed in a single risk_node invocation — not split
    across two runs where the first sees only license findings. Multiple
    runs would leave a window where pending_human_review reflects
    license-only state and DecisionGate has already interrupted.
    """
    g = _build_topology(cve_delay=0.3, defer_risk=True)
    values = _run_until_pause(g, "topo-one-run")

    runs = values.get("risk_runs", [])
    assert len(runs) == 1, (
        f"risk_node fired {len(runs)} times; expected exactly 1. runs={runs}"
    )
    assert runs[0]["lic"] == 1 and runs[0]["cve"] == 1, (
        f"risk_node's single run did not see both branches: {runs[0]}"
    )


def test_pending_human_review_includes_findings_from_both_branches():
    """At the HITL pause, pending_human_review reflects findings from
    both license and CVE branches — never just one."""
    g = _build_topology(cve_delay=0.3, defer_risk=True)
    values = _run_until_pause(g, "topo-pending")

    pending = values["pending_human_review"]
    pending_types = {f["type"] for f in pending}
    assert "license_violation" in pending_types
    assert "cve" in pending_types, (
        f"CVE finding missing from pending_human_review: {pending}"
    )
    assert values["status"] == "awaiting_human"


def test_real_graph_source_registers_risk_node_with_defer_true():
    """
    Lock the topology contract: graph.py must register risk_node as a
    deferred node so the runtime treats it as a join barrier. Without
    this flag, a fast license_node + slow cve_node race lets risk_node
    fire on license findings alone (see the diagnostic scripts in the
    PR description).

    The compiled PregelNode doesn't expose the `defer` flag as a public
    attribute — it's consumed by the compiler to wire triggers. The
    most robust check is on the source itself: anyone who removes
    `defer=True` from graph.py's risk_node registration will fail this
    test immediately.
    """
    import re
    graph_py = (PROJECT_ROOT / "graph.py").read_text()
    # Match `builder.add_node("risk_node", risk_node, defer=True)`
    # with flexible whitespace.
    pattern = re.compile(
        r'add_node\(\s*["\']risk_node["\']\s*,\s*risk_node\s*,'
        r'\s*defer\s*=\s*True',
        re.MULTILINE,
    )
    assert pattern.search(graph_py), (
        "graph.py must register risk_node with defer=True so it joins "
        "the parallel license_node + cve_node branches before "
        "DecisionGate can fire. Search for the comment block in graph.py "
        "for the architectural reasoning."
    )


# ---------------------------------------------------------------------------
# HITL interrupt + resume — regression for the "Submit Decision is a no-op"
# bug where resume_after_hitl called aupdate_state alone and never actually
# advanced execution past the interrupt.
# ---------------------------------------------------------------------------

def test_command_resume_advances_paused_graph_past_interrupt():
    """
    Behavioral lock: the LangGraph runtime supports advancing a paused
    graph via `graph.ainvoke(Command(resume=value), config)`. value is
    delivered as the return value of the suspended `interrupt(...)`
    call, and the node then runs its post-interrupt code.

    This is the pattern resume_after_hitl uses. If a future
    LangGraph version breaks this contract, this test catches it
    before the bug reaches production.
    """
    from langgraph.types import Command, interrupt as lg_interrupt
    from langgraph.checkpoint.memory import MemorySaver

    class S2(TypedDict, total=False):
        pending:  list
        resolved: Annotated[list, operator.add]
        status:   str

    async def gate(state):
        if state.get("pending"):
            decisions = lg_interrupt({"pending": state["pending"]})
            return {
                "resolved": list(decisions or []),
                "pending": [],
                "status": "done",
            }
        return {"status": "done"}

    b = StateGraph(S2)
    b.add_node("gate", gate)
    b.set_entry_point("gate")
    b.add_edge("gate", END)
    g = b.compile(checkpointer=MemorySaver())

    async def go():
        cfg = {"configurable": {"thread_id": "hitl-1"}}
        # Step 1: drive the graph until it hits interrupt.
        try:
            await g.ainvoke(
                {"pending": ["fid-1"], "resolved": [], "status": "running"},
                config=cfg,
            )
        except Exception:
            pass
        snap = await g.aget_state(cfg)
        assert snap.values.get("status") == "running", (
            "graph should be paused at interrupt with original status"
        )
        assert snap.values.get("resolved") == []

        # Step 2: resume with Command(resume=...). This is what
        # resume_after_hitl does. The gate node receives the decisions
        # list as the return value of its interrupt() call and runs its
        # post-interrupt code.
        await g.ainvoke(Command(resume=["d1"]), config=cfg)

        snap = await g.aget_state(cfg)
        assert snap.values.get("status") == "done", (
            f"graph did NOT advance past interrupt after Command(resume=...). "
            f"final state: {snap.values}"
        )
        assert snap.values.get("resolved") == ["d1"], (
            f"gate's post-interrupt code did not run: {snap.values}"
        )

    asyncio.run(go())


def test_aupdate_state_alone_does_not_advance_paused_graph():
    """
    Negative control: the OLD resume pattern (graph.aupdate_state with
    `{"__interrupt__": decisions}` + `as_node="..."` and NOTHING ELSE)
    does NOT advance the graph past the interrupt. This is exactly what
    resume_after_hitl used to do, and why Submit Decision was a no-op.

    If this test ever starts failing (i.e. aupdate_state alone DOES
    advance the graph), it means the LangGraph runtime changed and
    the documented bug history in graph.py needs revision.
    """
    from langgraph.types import interrupt as lg_interrupt
    from langgraph.checkpoint.memory import MemorySaver

    class S3(TypedDict, total=False):
        pending:  list
        resolved: Annotated[list, operator.add]
        status:   str

    async def gate(state):
        if state.get("pending"):
            decisions = lg_interrupt({"pending": state["pending"]})
            return {
                "resolved": list(decisions or []),
                "pending": [],
                "status": "done",
            }
        return {"status": "done"}

    b = StateGraph(S3)
    b.add_node("gate", gate)
    b.set_entry_point("gate")
    b.add_edge("gate", END)
    g = b.compile(checkpointer=MemorySaver())

    async def go():
        cfg = {"configurable": {"thread_id": "hitl-2"}}
        try:
            await g.ainvoke(
                {"pending": ["fid-1"], "resolved": [], "status": "running"},
                config=cfg,
            )
        except Exception:
            pass
        # Use the OLD pattern: aupdate_state alone, no ainvoke.
        await g.aupdate_state(
            cfg, {"__interrupt__": ["d1"]}, as_node="gate"
        )
        snap = await g.aget_state(cfg)
        # The graph did NOT advance: gate's post-interrupt code didn't run.
        assert snap.values.get("status") == "running"
        assert snap.values.get("resolved") == []

    asyncio.run(go())


def test_resume_after_hitl_uses_ainvoke_with_command_resume():
    """
    Contract lock on the production graph.resume_after_hitl. It MUST
    call graph.ainvoke with a Command(resume=decisions) argument so
    the paused decision_gate_node receives the decisions and executes
    its post-interrupt code.

    The legacy implementation called only graph.aupdate_state(...) and
    skipped ainvoke — leaving the graph paused forever. This test
    intercepts graph.ainvoke and asserts on the call shape so any
    regression to the old pattern fails the build.
    """
    import asyncio
    from unittest.mock import AsyncMock, patch
    from langgraph.types import Command
    from graph import resume_after_hitl
    import graph as graph_module

    decisions = [{
        "finding_id": "f-x",
        "decision_status": "accepted",
        "rationale": "ok",
        "decided_by": "demo@test",
    }]

    captured = {}
    async def fake_ainvoke(input_, *, config=None):
        captured["input"] = input_
        captured["config"] = config
        return {}

    with patch.object(graph_module.graph, "ainvoke", new=fake_ainvoke):
        asyncio.run(resume_after_hitl("job-x", decisions))

    assert isinstance(captured.get("input"), Command), (
        "resume_after_hitl must call graph.ainvoke with a Command(...) "
        "input, not aupdate_state alone."
    )
    # Command(resume=...) is the canonical resume payload.
    assert captured["input"].resume == decisions, (
        f"Command.resume payload should be the decisions list; got "
        f"{captured['input'].resume!r}"
    )
    # The config must scope the resume to this job's thread_id.
    assert captured["config"]["configurable"]["thread_id"] == "job-x"


# ---------------------------------------------------------------------------
# audit_node fan-in join barrier — regression for the smoke-tested P0 where
# the audit chain sealed after ONE decision out of 42 because audit_node
# fired as soon as the fastest of its three predecessors completed (the
# synchronous auto_remediate_node), without waiting for decision_gate_node
# to drain pending_human_review across multiple resume cycles.
# ---------------------------------------------------------------------------

def test_real_graph_source_registers_audit_node_with_defer_true():
    """
    Contract lock: graph.py must register audit_node with defer=True
    so the runtime joins its three parallel predecessors
    (decision_gate_node, auto_remediate_node, auto_accept_node)
    before sealing the audit chain.

    Without this flag, the synchronous auto_remediate_node completes
    first, audit_node sees one ready trigger, and fires — sealing the
    chain while decision_gate_node is still cycling through pending
    findings. The user-visible symptom is the HITL chain sealing
    after the first decision (BUGS.md P0, 2026-05-17 smoke test).

    The compiled PregelNode doesn't expose the defer flag as a public
    attribute; we check the source like we do for risk_node.
    """
    import re
    graph_py = (PROJECT_ROOT / "graph.py").read_text()
    pattern = re.compile(
        r'add_node\(\s*["\']audit_node["\']\s*,\s*audit_node\s*,'
        r'\s*defer\s*=\s*True',
        re.MULTILINE,
    )
    assert pattern.search(graph_py), (
        "graph.py must register audit_node with defer=True so the "
        "audit chain seal waits for all three decision branches "
        "(decision_gate_node, auto_remediate_node, auto_accept_node) "
        "before firing. See the comment block in graph.py near the "
        "audit_node registration for the architectural reasoning."
    )


def test_audit_node_waits_for_partial_decision_resume_cycle():
    """
    Behavioral test: a minimal LangGraph that mirrors the production
    fan-in at audit_node (three predecessors: a synchronous
    auto_remediate stub, a synchronous auto_accept stub, and a
    decision_gate stub that calls interrupt() until all findings are
    decided). With audit_node registered defer=True, the chain MUST
    NOT seal after only one decision is resumed; it must wait for
    decision_gate to fully drain pending_human_review.

    This is the regression test for the smoke-tested P0 (job
    job-6f1b8db0-...). Pre-fix: audit_node would fire alongside the
    first decision_gate resume and stamp `audit_chain_sealed`. Post-
    fix: audit_node holds until pending is empty.
    """
    from langgraph.types import interrupt as lg_interrupt

    class AS(TypedDict, total=False):
        pending_human_review: list
        resolved_findings:    Annotated[list, operator.add]
        auto_remediated:      Annotated[list, operator.add]
        auto_accepted:        Annotated[list, operator.add]
        audit_chain_sealed:   bool
        status:               str

    async def gate(state):
        if state.get("pending_human_review"):
            decisions = lg_interrupt({"pending": state["pending_human_review"]})
            decisions = list(decisions or [])
            still_pending = list(state["pending_human_review"])
            resolved = []
            for d in decisions:
                fid = d.get("finding_id")
                m = next((f for f in still_pending if f["finding_id"] == fid), None)
                if m:
                    still_pending = [f for f in still_pending if f["finding_id"] != fid]
                    resolved.append({**m, "decision_status": d.get("decision_status")})
            return {"pending_human_review": still_pending, "resolved_findings": resolved}
        return {}

    async def auto_remediate(state):
        # Synchronous, completes near-instantly. Pre-fix this would
        # trigger audit_node alone.
        return {"auto_remediated": ["a1", "a2"]}

    async def auto_accept(state):
        return {"auto_accepted": []}

    async def audit(state):
        return {"audit_chain_sealed": True, "status": "complete"}

    def route_after_risk(_state):
        return ["gate", "auto_remediate", "auto_accept"]

    def route_to_audit(state):
        return "gate" if state.get("pending_human_review") else "audit"

    def _build(*, defer_audit: bool):
        b = StateGraph(AS)
        # entry shim that fans out to all three branches
        async def risk(state): return {}
        b.add_node("risk", risk)
        b.add_node("gate", gate)
        b.add_node("auto_remediate", auto_remediate)
        b.add_node("auto_accept", auto_accept)
        if defer_audit:
            b.add_node("audit", audit, defer=True)
        else:
            b.add_node("audit", audit)
        b.set_entry_point("risk")
        b.add_conditional_edges("risk", route_after_risk)
        b.add_conditional_edges("gate", route_to_audit)
        b.add_edge("auto_remediate", "audit")
        b.add_edge("auto_accept", "audit")
        b.add_edge("audit", END)
        return b.compile(checkpointer=MemorySaver())

    async def go():
        # WITH defer=True (the fixed behavior): partial resume must
        # NOT seal the chain.
        g = _build(defer_audit=True)
        cfg = {"configurable": {"thread_id": "audit-defer"}}
        initial = {
            "pending_human_review": [
                {"finding_id": "f1"}, {"finding_id": "f2"}, {"finding_id": "f3"},
            ],
            "resolved_findings": [], "auto_remediated": [], "auto_accepted": [],
            "audit_chain_sealed": False, "status": "awaiting_human",
        }
        await g.ainvoke(initial, config=cfg)

        # Resume with ONE decision out of three pending.
        from langgraph.types import Command
        await g.ainvoke(
            Command(resume=[{"finding_id": "f1", "decision_status": "accepted"}]),
            config=cfg,
        )

        snap = await g.aget_state(cfg)
        v = snap.values
        # Two findings still pending — audit_node MUST NOT have fired.
        assert len(v["pending_human_review"]) == 2, (
            f"pending_human_review wrong after partial resume: {v}"
        )
        assert v.get("audit_chain_sealed") is False, (
            "audit_node fired prematurely on partial decision resume; "
            "defer=True is not holding the join barrier"
        )
        assert v.get("status") != "complete", (
            f"status flipped to complete with pending findings: {v.get('status')!r}"
        )

        # Now resume the remaining two — chain should seal.
        await g.ainvoke(
            Command(resume=[
                {"finding_id": "f2", "decision_status": "deferred"},
                {"finding_id": "f3", "decision_status": "auto_remediate"},
            ]),
            config=cfg,
        )
        snap = await g.aget_state(cfg)
        v = snap.values
        assert v["pending_human_review"] == []
        assert v.get("audit_chain_sealed") is True, (
            "audit_node didn't fire even after all pending findings were "
            f"resolved: {v}"
        )
        assert v.get("status") == "complete"

    asyncio.run(go())
