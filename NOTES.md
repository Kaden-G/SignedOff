# SignedOff Engineering Notes

## LangGraph state-persistence contract (the lesson of May 17)

LangGraph's checkpointer deserializes each state field into an
INDEPENDENT object on every super-step. Mutating a dict referenced
from one state field does NOT propagate to other state fields that
referenced the same dict before serialization.

In practice: if a node mutates `finding["decision_status"]` on a
Finding it pulled from `state["pending_human_review"]`, that mutation
is ONLY visible to readers of `state["pending_human_review"]` after
the node returns. Readers of `state["cve_findings"]` (or
`state["license_findings"]`) see the pre-mutation version, even
though those lists held the same Python object on the way IN.

### The rule

**Every node that mutates a Finding (or any shared dict) in place
MUST include each affected list in its return dict.** Otherwise the
mutation is silently dropped between super-steps.

### Bugs caused by this trap (all resolved)

- `risk_node` Stage-1 routing (d1c71f8): mutated decision_status in
  place; license findings happened to work because LicenseNode
  pre-stamped HUMAN_REVIEW at construction; CVE findings stayed at
  PENDING. Fix: return license_findings + cve_findings from risk_node.
- `decision_gate_node` post-interrupt (83f2dcf): mutated decision_status
  on findings reached via pending_human_review; canonical
  license_findings/cve_findings lists held independent copies and
  didn't see the mutation. Fix: mirror the mutation onto canonical
  lists AND include them in return dict.
- `graph.resume_after_hitl` (170d882): not the same trap, but adjacent.
  aupdate_state writes checkpoint but doesn't advance execution; must
  use ainvoke(Command(resume=...)) to actually resume past interrupt().

### Suspected remaining exposure (untested)

- `auto_remediate_node`: probably mutates findings in place. Audit
  needed.
- `auto_accept_node`: same.
- `risk_node` contextualization step: mutates contextualized_severity
  and contextualization_rationale on findings. Currently survives
  because risk_node returns license_findings + cve_findings (per
  d1c71f8), but the dependency is implicit, not documented.

### Future hardening ideas

- Helper function: `propagate_to_canonical(finding, license_findings, cve_findings)`
  that mirrors the mutation onto whichever list owns it. Used after
  every in-place mutation.
- Convention: any function that mutates a Finding returns a tuple
  `(finding, canonical_list_field_name)` instead of mutating directly.
- Or: lint rule that flags in-place dict mutation inside any node
  whose return dict doesn't include the corresponding field.

## Metadata staleness bug (P3, logged 2026-05-17)

`_run_graph_safely` sets `_job_metadata[job_id]["status"] = "complete"`
after the first `ainvoke` returns. This is incorrect when the graph
paused at the HITL interrupt — the graph isn't complete, it's just
waiting for input. Currently doesn't affect `/scan/status` because
that endpoint reads from graph state (not metadata), but it's a
latent footgun if anything ever reads from metadata.

## Over-mocked tests (logged 2026-05-17)

`tests/test_api.py::test_post_decision_valid_resolves_finding_and_returns_state`
patches `api.resume_after_hitl` with AsyncMock(return_value=None). That
mock is why the original resume-doesn't-actually-resume bug shipped to
the UI. The test passed because the mock returned cleanly; the real
function silently failed.

Audit other tests for similar shadowing. Candidates to spot-check:
- anything in test_api.py that patches a node or graph function
- anything in test_decision_nodes.py that mocks the interrupt mechanism
