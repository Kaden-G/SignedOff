"""
graph.py
========
LangGraph state graph definition for the SignedOff compliance agent.

This file is the ONLY place where graph topology is defined — which nodes
exist, which edges connect them, and which conditional branches route state
between them. Node implementations live in nodes/*.py. This file wires
them together.

Graph shape:
                        ┌─────────────┐
                        │  InputNode  │
                        └──────┬──────┘
                               │
                        ┌──────▼──────┐
                        │  SBOMNode   │
                        └──────┬──────┘
                               │
               ┌───────────────┼───────────────┐
               │  (parallel)                   │
        ┌──────▼──────┐               ┌────────▼────────┐
        │ LicenseNode │               │    CVENode      │
        └──────┬──────┘               └────────┬────────┘
               │                               │
               └───────────────┬───────────────┘
                               │  (both must complete)
                        ┌──────▼──────┐
                        │  RiskNode   │
                        └──────┬──────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
       ┌──────▼──────┐  ┌──────▼──────┐  ┌─────▼──────┐
       │   HITL      │  │    Auto     │  │    Auto    │
       │ DecisionGate│  │  Remediate  │  │   Accept  │
       └──────┬──────┘  └──────┬──────┘  └─────┬──────┘
              │                │                │
              └────────────────┼────────────────┘
                               │  (all findings resolved)
                        ┌──────▼──────┐
                        │  AuditNode  │  ← seals the hash chain
                        └──────┬──────┘
                               │
                        ┌──────▼──────┐
                        │ ReportNode  │
                        └─────────────┘

Parallelism:
    LicenseNode and CVENode run as a true parallel branch using LangGraph's
    native fan-out support. Both nodes receive the same state after SBOMNode
    completes. RiskNode acts as the implicit fan-in — it only runs after
    BOTH parallel branches have written their findings to state.

    This is safe because:
    - LicenseNode writes ONLY to: license_findings, errors, audit_events
    - CVENode writes ONLY to:     cve_findings, errors, audit_events
    - Neither touches the other's output field
    - errors and audit_events use operator.add reducers (safe concurrent appends)

HITL interrupt:
    DecisionGateNode calls langgraph.types.interrupt() when findings are
    pending human review. The graph pauses. The FastAPI endpoint
    POST /scan/decision/{finding_id} resumes it by providing the human
    decisions via graph.update_state().

    LangGraph's checkpointer handles state persistence across the interrupt.
    For v1 this uses MemorySaver (in-process). v2 would use PostgresSaver.

Audit trail:
    Nodes do NOT hash-chain their own audit entries. They append raw events
    to state["audit_events"] (a staging field, not the final audit_trail).
    AuditNode runs last, sorts all events by timestamp, and writes the
    hash-chained audit_trail in one deterministic pass.

    This guarantees:
    - Hash chain ordering is deterministic regardless of parallel execution
    - The chain is "sealed" at a single terminal point
    - No partial chains exist mid-scan
"""

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from agent_state import AgentState
from nodes.input_node import input_node
from nodes.sbom_node import sbom_node
from nodes.license_node import license_node
from nodes.cve_node import cve_node
from nodes.risk_node import risk_node
from nodes.decision_gate_node import decision_gate_node
from nodes.auto_remediate_node import auto_remediate_node
from nodes.auto_accept_node import auto_accept_node
from nodes.audit_node import audit_node
from nodes.report_node import report_node


# ---------------------------------------------------------------------------
# Routing functions
# These are pure functions — they read state and return a node name string
# (or list of node names for fan-out). They contain NO business logic.
# Business logic lives in the nodes. Routers just read status flags.
# ---------------------------------------------------------------------------

def route_after_risk(state: AgentState) -> list[str]:
    """
    Fan-out routing after RiskNode.

    RiskNode sets decision_status on every finding in risk_matrix.
    This router checks which buckets are populated and fires the
    corresponding downstream nodes — potentially multiple simultaneously.

    Returns a list of node names to execute next. LangGraph fires all
    of them in parallel if multiple are returned.

    Invariant: AuditNode must NOT be reachable from here. We only go to
    AuditNode after all three decision branches have converged. That
    convergence is handled by route_to_audit() below.
    """
    destinations = []

    # Are there findings requiring human review?
    if state.get("pending_human_review"):
        destinations.append("decision_gate_node")

    # Are there findings the policy says to auto-remediate?
    auto_remediate = [
        f for f in state.get("resolved_findings", [])
        if f["decision_status"] == "auto_remediate"
    ]
    if auto_remediate:
        destinations.append("auto_remediate_node")

    # Are there findings the policy says to auto-accept?
    auto_accept = [
        f for f in state.get("resolved_findings", [])
        if f["decision_status"] == "accepted"
        and f.get("decided_by") == "auto"
    ]
    if auto_accept:
        destinations.append("auto_accept_node")

    # Safety valve: if RiskNode produced no findings at all (clean project),
    # skip all decision nodes and go straight to audit.
    if not destinations:
        return ["audit_node"]

    return destinations


def route_to_audit(state: AgentState) -> str:
    """
    Convergence check before AuditNode.

    All three decision branches (HITL, auto-remediate, auto-accept) must
    complete before AuditNode runs. This router checks whether any findings
    are still pending.

    If pending_human_review is non-empty, a human hasn't finished yet —
    stay in decision_gate_node (LangGraph interrupt keeps us there anyway,
    but this makes the routing explicit).

    Once pending_human_review is empty AND all resolved_findings have
    terminal statuses, we proceed to AuditNode.

    Note: In practice the interrupt() in DecisionGateNode handles the
    pause. This router is the explicit graph-level signal that we're done.
    """
    if state.get("pending_human_review"):
        # Still waiting on human decisions — loop back to gate
        # (This path is hit after the interrupt resumes and we check
        # whether the human resolved ALL pending findings or just some)
        return "decision_gate_node"

    # All findings resolved — seal the audit trail
    return "audit_node"


def route_after_input(state: AgentState) -> str:
    """
    Guard after InputNode.

    If InputNode encountered a fatal validation error (bad repo URL,
    malformed POLICY.yml, invalid use_case), status is set to "failed"
    and we skip the entire pipeline — nothing to scan.

    On success, proceed to SBOM resolution.
    """
    if state.get("status") == "failed":
        return END
    return "sbom_node"


def route_after_sbom(state: AgentState) -> str:
    """
    Guard after SBOMNode.

    If the dependency tree is empty (no packages found — wrong file path,
    empty requirements.txt, etc.) or SBOM resolution failed fatally,
    short-circuit to audit (records the attempt) then report (surfaces
    the error to the user).

    On success, fan out to parallel license + CVE analysis.
    """
    if state.get("status") == "failed":
        return "audit_node"

    if not state.get("packages"):
        # No packages found — not a fatal error, but nothing to analyze.
        # AuditNode will record the empty scan. ReportNode will surface it.
        return "audit_node"

    # Normal path — fan out to both analysis nodes simultaneously.
    # Returning a string here means "go to this node" — the parallel
    # fan-out to BOTH license_node AND cve_node is declared as explicit
    # edges in the graph definition below, not via this router.
    return "parallel_analysis"  # sentinel — see add_conditional_edges below


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph() -> StateGraph:
    """
    Construct and compile the SignedOff compliance agent graph.

    Called once at application startup. The compiled graph is stored as a
    module-level singleton (see bottom of file) and reused across requests.

    Returns the compiled graph ready for graph.invoke() or graph.stream().
    """
    builder = StateGraph(AgentState)

    # ------------------------------------------------------------------
    # Register nodes
    # Order here is documentation only — actual execution order is
    # determined by edges below.
    # ------------------------------------------------------------------
    builder.add_node("input_node",          input_node)
    builder.add_node("sbom_node",           sbom_node)
    builder.add_node("license_node",        license_node)
    builder.add_node("cve_node",            cve_node)
    builder.add_node("risk_node",           risk_node)
    builder.add_node("decision_gate_node",  decision_gate_node)
    builder.add_node("auto_remediate_node", auto_remediate_node)
    builder.add_node("auto_accept_node",    auto_accept_node)
    builder.add_node("audit_node",          audit_node)
    builder.add_node("report_node",         report_node)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    builder.set_entry_point("input_node")

    # ------------------------------------------------------------------
    # input_node → sbom_node (or END on fatal error)
    # ------------------------------------------------------------------
    builder.add_conditional_edges(
        "input_node",
        route_after_input,
        {
            "sbom_node": "sbom_node",
            END: END,
        }
    )

    # ------------------------------------------------------------------
    # sbom_node → [license_node, cve_node] in parallel
    #
    # LangGraph fires both edges simultaneously after sbom_node completes.
    # RiskNode is the implicit fan-in — it only runs after BOTH branches
    # have appended to license_findings and cve_findings respectively.
    #
    # The conditional edge handles the empty-packages short-circuit.
    # ------------------------------------------------------------------
    builder.add_conditional_edges(
        "sbom_node",
        route_after_sbom,
        {
            "parallel_analysis": ["license_node", "cve_node"],  # true parallel
            "audit_node": "audit_node",                         # empty/failed
        }
    )

    # ------------------------------------------------------------------
    # license_node → risk_node  (fan-in leg 1)
    # cve_node     → risk_node  (fan-in leg 2)
    #
    # LangGraph merges state from both parallel branches before invoking
    # risk_node. risk_node sees both license_findings AND cve_findings
    # fully populated when it runs.
    # ------------------------------------------------------------------
    builder.add_edge("license_node", "risk_node")
    builder.add_edge("cve_node",     "risk_node")

    # ------------------------------------------------------------------
    # risk_node → [decision_gate_node, auto_remediate_node, auto_accept_node]
    #
    # Up to all three can fire simultaneously if the risk matrix contains
    # findings in multiple decision buckets. Most real scans will have
    # findings in at least two buckets (some HITL, some auto).
    # ------------------------------------------------------------------
    builder.add_conditional_edges(
        "risk_node",
        route_after_risk,
        {
            "decision_gate_node":  "decision_gate_node",
            "auto_remediate_node": "auto_remediate_node",
            "auto_accept_node":    "auto_accept_node",
            "audit_node":          "audit_node",   # clean project path
        }
    )

    # ------------------------------------------------------------------
    # decision_gate_node → audit_node (or loop back to self)
    #
    # DecisionGateNode calls interrupt() when findings are pending.
    # After the human resolves findings via POST /scan/decision/{id},
    # LangGraph resumes here. route_to_audit checks whether ALL findings
    # are resolved before proceeding.
    # ------------------------------------------------------------------
    builder.add_conditional_edges(
        "decision_gate_node",
        route_to_audit,
        {
            "decision_gate_node": "decision_gate_node",  # more findings pending
            "audit_node":         "audit_node",
        }
    )

    # ------------------------------------------------------------------
    # auto_remediate_node → audit_node
    # auto_accept_node    → audit_node
    #
    # Both auto-decision nodes go directly to audit once complete.
    # If decision_gate_node is ALSO running in parallel, audit_node
    # waits for ALL incoming edges to complete (LangGraph fan-in behavior).
    # ------------------------------------------------------------------
    builder.add_edge("auto_remediate_node", "audit_node")
    builder.add_edge("auto_accept_node",    "audit_node")

    # ------------------------------------------------------------------
    # audit_node → report_node → END
    # ------------------------------------------------------------------
    builder.add_edge("audit_node",  "report_node")
    builder.add_edge("report_node", END)

    # ------------------------------------------------------------------
    # Compile with MemorySaver checkpointer
    #
    # MemorySaver stores graph state in-process (no external DB needed).
    # Required for the interrupt() pattern in DecisionGateNode — LangGraph
    # needs a checkpointer to pause and resume across HTTP requests.
    #
    # v2: Replace with AsyncPostgresSaver for production persistence.
    # ------------------------------------------------------------------
    checkpointer = MemorySaver()
    return builder.compile(checkpointer=checkpointer)


# ---------------------------------------------------------------------------
# Module-level singleton
#
# Build once at import time. Reused across all FastAPI requests.
# graph.invoke() and graph.stream() are both thread-safe on the compiled
# graph object — LangGraph isolates state per thread_id/config.
# ---------------------------------------------------------------------------
graph = build_graph()


# ---------------------------------------------------------------------------
# Convenience: thread config factory
#
# Every graph.invoke() / graph.stream() call needs a config dict with a
# thread_id so the checkpointer can isolate state per scan job.
# Use the job_id as the thread_id — one thread per scan.
#
# Usage in api.py:
#   result = await graph.ainvoke(initial_state, config=make_config(job_id))
# ---------------------------------------------------------------------------
def make_config(job_id: str) -> dict:
    """
    Build the LangGraph run config for a given scan job.

    The thread_id is what the MemorySaver uses to namespace state.
    Using job_id as thread_id means:
      - Each scan is isolated (no state bleed between concurrent scans)
      - The checkpointer can resume an interrupted scan by job_id
      - GET /scan/status/{job_id} can read state by job_id

    Args:
        job_id: The scan job identifier from AgentState["job_id"].
                Format: "job-{uuid4}"

    Returns:
        Config dict ready to pass as the `config` kwarg to graph.ainvoke()
        or graph.astream().
    """
    return {
        "configurable": {
            "thread_id": job_id,
        }
    }


# ---------------------------------------------------------------------------
# Convenience: resume after HITL interrupt
#
# After a human submits decisions via POST /scan/decision/{finding_id},
# api.py calls this to inject the decisions back into the paused graph
# and resume execution.
#
# Usage in api.py:
#   await resume_after_hitl(job_id, decisions)
# ---------------------------------------------------------------------------
async def resume_after_hitl(job_id: str, decisions: list[dict]) -> None:
    """
    Resume a graph that is paused at the DecisionGateNode interrupt.

    Injects human decisions into the graph state and resumes execution
    from the interrupt point. LangGraph replays from the checkpoint,
    applying the injected decisions.

    Args:
        job_id:    The scan job to resume. Used as thread_id for checkpointer.
        decisions: List of decision dicts, each with:
                   {
                     "finding_id": str,       # matches Finding.finding_id
                     "decision_status": str,  # "accepted" | "deferred" |
                                              # "auto_remediate"
                     "rationale": str,        # required for accepted/deferred
                     "decided_by": str,       # user identifier
                   }
    """
    config = make_config(job_id)

    # LangGraph's interrupt resume pattern:
    # graph.update_state() injects the human response as the interrupt's
    # return value. The next graph.ainvoke() call resumes from that point.
    await graph.aupdate_state(
        config,
        {"__interrupt__": decisions},
        as_node="decision_gate_node",
    )
