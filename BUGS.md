# SignedOff Known Issues

This file tracks known limitations, bugs, and v1.1 polish opportunities
identified during v1 development. Issues are categorized by severity:

- **P0**: Demo blocker, fix immediately
- **P1**: Important but not demo-blocking, fix Sunday or after
- **P2**: Polish, fix opportunistically
- **P3**: Documented behavior / known limitation, don't fix

---

## ✅ PRE-DEPLOY ALERT (2026-05-17 smoke test → 2026-05-18 fixes)

The v1.0-final tag `v1.0-backend-complete` (commit `83f2dcf`, 175 tests
passing) was smoke-tested against three previously-unverified input
paths. Two P0 issues surfaced. **Both resolved on 2026-05-18.** Pre-fix
state preserved at tag `v1.0-final-pre-p0` for rollback. See
`## Smoke Test Results (2026-05-17 evening)` below for the original
reproductions. Headline status:

- **P0a — RESOLVED (commit `f240469`).** Audit chain sealed after the
  first decision when 41 of 42 HITL findings were still undecided;
  `status` flipped to `"complete"` prematurely. Fixed by adding
  `defer=True` to `audit_node` registration in `graph.py`, mirroring
  the `risk_node` fix from `47f30e1`. Two regression tests added in
  `tests/test_graph_topology.py` (source-contract check +
  behavioral test that submits one decision out of three and asserts
  the audit chain does NOT seal).
- **P0b — RESOLVED (commit `c285613`).** `input_type="repo_url"` was
  accepted but the URL was never fetched; SBOMNode returned the
  server's venv as findings. Fixed by dropping `repo_url` from the
  `Literal` in `api.py`'s `ScanStartRequest`. Callers now get 422
  with `msg: "Input should be 'requirements_file'"`. Defense-in-depth
  check added to `nodes/input_node.py`'s `VALID_INPUT_TYPES`
  frozenset. Dead branch in `nodes/sbom_node.py` removed. One
  regression test added in `tests/test_api.py`. Real repo URL
  ingestion is v1.1 roadmap.

- **P1 (use_case threading in LicenseNode) — RESOLVED.** Design 1
  applied: `licenses.blocked` is now a dict keyed by use_case. GPL-3.0
  + use_case=internal no longer fires CRITICAL (the blocked fast-path
  is skipped because `blocked.internal == []`). Audit-traceable via
  the new `policy.licenses.blocked.{use_case}[{license_id}]` citation
  identifier. Backward compat preserved for legacy flat-list policies.
  See `## ✅ USE_CASE INVESTIGATION — 2026-05-18 (RESOLVED)` below.

Suite after fixes: 193 passed (175 v1.0-final + 3 P0 regression tests
+ 15 use_case matrix tests).

---

## P0 — Demo blockers

### P0 — Audit chain seals prematurely after first decision (audit_node missing `defer=True`)

**Surface:** Submit ONE decision out of N pending via
`POST /scan/decision/{finding_id}`. The decision endpoint correctly
reports `pending_remaining: 41, graph_status: "awaiting_human"`, but
`GET /scan/status/{job_id}` returns `status: "complete"` and the
audit trail shows an `audit_sealed` event. 41 findings remain at
`decision_status: "human_review"` in `/scan/results` but the graph
behaves as if all decisions are in.

**Reproduction:** Boot uvicorn fresh, kick off a scan with
`use_case=saas` against `demo_requirements.txt`. Wait for
`awaiting_human` (42 pending findings expected). Submit one decision
via curl. Then:

```
curl /scan/status/$JOB_ID
  → "status":"complete"             ← WRONG (should be awaiting_human)

curl /audit/trail/$JOB_ID
  → seal_status:"complete"
  → final event: audit_sealed       ← WRONG (should not have sealed)
  → entry #6: auto_remediation_applied count=71
  → entry #7: human_decisions_recorded (only 1 decision)
  → entry #8: audit_sealed          ← FIRED AFTER ONE DECISION
```

Captured live during the 2026-05-17 evening smoke test on job
`job-6f1b8db0-7791-4a0f-b529-5d6783c3eafd`. Verified that decision
flow itself works: target finding shows
`decision_status: "accepted", decided_by: "smoke@test"` correctly.
The bug is in graph topology, not in decision_gate_node.

**Root cause (hypothesis, not verified):** `audit_node` is the join
point for THREE parallel branches in `graph.py`:
- `decision_gate_node` → conditional edge `route_to_audit`
- `auto_remediate_node` → direct edge
- `auto_accept_node` → direct edge

Without `defer=True`, LangGraph's Pregel runtime fires `audit_node`
as soon as enough triggers are ready, not after ALL three branches
have either reached it or been definitively routed elsewhere.
`auto_remediate_node` completes first (71 findings, no I/O). On
resume after the first decision, `audit_node` runs even though
`route_to_audit` should loop back to `decision_gate_node` because
`pending_human_review` still has 41 entries.

This is the same defer-barrier pattern fixed for `risk_node` in
commit `47f30e1` — same diagnosis applies one level downstream.

**Impact:** Demo-blocking.
- The HITL mic-drop ("submit decision, watch chain seal at the
  end") is broken — the chain seals after the first click.
- "Verify Chain Now" reports PASS on a chain that doesn't represent
  the human review state (40+ findings still unresolved).
- Reviewers see findings flip to `decision_status: "accepted"` only
  one at a time while `status` says "complete", inviting "wait, is
  the scan done or not?" confusion.

**Suggested fix (NOT applied per task constraints):**
```python
# graph.py, in build_graph(), register audit_node with defer=True:
builder.add_node("audit_node", audit_node, defer=True)
```

Then re-verify with the smoke-test repro above. Add a regression
test in `tests/test_graph_topology.py` mirroring the join-barrier
test pattern from `test_risk_node_runs_after_both_branches_complete`
(commit `47f30e1`). Estimated effort: 15 min code + 30 min test.

**Workaround for demo if fix can't ship:** Demo only ONE decision
submission, frame it as "scan auto-seals once the first decision
lands as a v1 design choice; v1.1 will hold the chain open for the
remaining findings." Honest framing avoids the credibility hit.

---

### P0 — `input_type="repo_url"` returns server's local venv as if it were the repo's deps

**Surface:** POST `/scan/start` with `input_type="repo_url"` and any
GitHub URL. The API returns 200, the scan proceeds, and the results
look like a normal scan of the requested URL. **But the URL is never
fetched.** SBOMNode reads `pipdeptree` against the server's running
venv and returns whatever's installed there — 151 packages from
SignedOff's own dependency graph (`django`, `paramiko`, `pytest`,
etc.).

**Reproduction:** Captured live on job
`job-5493925b-519d-4a81-9564-7da60d9d9c88` during the 2026-05-17
evening smoke test:
```
POST /scan/start {"input_type":"repo_url","input_value":"https://github.com/Kaden-G/lablab-prep","use_case":"saas"}
  → 200, runs scan
GET /scan/results/$JOB → 151 packages including django, paramiko,
  text-unidecode (SignedOff's own deps, NOT lablab-prep's deps)
GET /scan/status/$JOB → errors[0]:
  "repo_url path is a v1 stub: dependencies are read from the
   running venv; direct/transitive classification falls back to
   pipdeptree tree position"
```

The error IS surfaced in `state["errors"]`. The dashboard probably
doesn't render it prominently.

**Root cause (already documented in `nodes/sbom_node.py:319`):**
v1 SBOMNode never implemented repo cloning. The `repo_url` branch
falls through to the same `pipdeptree`-on-running-venv path as
`requirements_file`. The input_value (the URL string) is dropped on
the floor.

**Impact:**
- **Dashboard demo risk: LOW.** `static/index.html:404` hardcodes
  `input_type: "requirements_file"`. There's no repo_url input in
  the UI. Demo-via-UI is safe.
- **API demo risk: HIGH.** If anyone exercises the API directly
  (Postman, curl, swagger), they get plausible-looking results
  attributed to the wrong codebase. Reputationally bad: the
  vulnerability findings appear to belong to whatever repo URL was
  submitted, but they actually describe the server. An auditor
  shown these results would draw wrong conclusions.

**Suggested fix options (NOT applied):**
- **Cheapest:** API-level reject. In `api.py`'s `ScanStartRequest`,
  drop `repo_url` from the `input_type` Literal so the endpoint
  returns 422 on submission. Honest "not implemented" failure.
- **Better for v1.1:** Implement minimum-viable repo URL handling:
  `git clone --depth 1`, find `requirements.txt` at root, send it
  through the existing `requirements_file` path. Or fall back to
  the cheapest option for now and document repo_url as a v1.1
  roadmap item.

**Workaround for demo:** No code change needed if demo stays on the
dashboard. Add a note to the writeup: "Repo URL input is v1.1
roadmap; v1 supports requirements.txt upload only."

---

## P1 — Fix soon

### P1 — Context-aware remediations have empty target_version

**Surface:** LLM contextualization recommendations sometimes mention specific
version numbers in their description (e.g. "Upgrade certifi to 2024.7.4 or
later"), but the structured `target_version` field on the context-aware
Remediation is `None` because the contextualization code in `risk_node.py`
doesn't extract version numbers from LLM prose.

**Impact:** UI can render the prose recommendation correctly, but cannot
populate a clean "Upgrade Available: X.Y.Z" badge or auto-PR target from the
context-aware Remediation's structured fields. Reviewers must read the prose
to see the recommended version.

**Reproduction:** Run `smoke_test.py` against `demo_requirements.txt` with
`use_case=saas`. Inspect `certifi 2024.2.2` contextualized findings — the
second remediation's description says "Upgrade certifi to 2024.7.4 or later"
but `target_version` is `None`.

**Fix path (v1.1):** Either ask the LLM to output a structured
`target_version` field alongside `contextualized_recommendation`, or do
post-hoc regex extraction from the description prose. LLM extraction is
cleaner. Estimated effort: 30 min.

---

### P1 — OSV version_bump remediation sometimes returns commit hash instead of release version

**Surface:** When OSV's `affected[].ranges` entry lists a fix as a commit SHA
(because no released version exists yet, or the fix is on `main`), the
`version_bump` remediation's `target_version` field contains the
40-character commit hash (e.g. `bd8153872e9c6fc98f4023df9c2deaffea2fa463`)
instead of a human-readable version number.

**Impact:** UI renders `Upgrade certifi from 2024.2.2 to bd8153872e9c...`
which is technically correct but useless to end users — nobody installs a
Python package by commit SHA in production.

**Reproduction:** Run `smoke_test.py` against `demo_requirements.txt`.
Inspect `certifi 2024.2.2` finding from OSV `PYSEC-2024-230` — the
`version_bump` remediation's `target_version` is a git hash.

**Fix path (v1.1):** In `nodes/cve_node.py`, detect when `target_version`
matches a SHA pattern (40 hex chars) and either:
- (a) drop the remediation entirely and emit a `no_fix_available`
  remediation with rationale "fix is on main but no released version yet", or
- (b) attempt to map the commit to a release tag via the package's GitHub API.

Option (a) is simpler. Estimated effort: 45 min.

---

## P2 — Polish

### P2 — UI rendering hint for dual same-type remediations

**Surface:** When a CVE finding's context-aware remediation comes back as
`version_bump` (the most common case), the Finding now has TWO remediations
of the same type:

- `remediations[0]`: `type=version_bump`, citation=`osv`, "Upgrade X to Y"
- `remediations[1]`: `type=version_bump`, citation=`llm_inference`, "Upgrade X to Y'"

The two are conceptually different (authoritative OSV fix vs LLM-suggested
recommendation, which may include alternatives like "or later"), but the UI
must avoid showing them as "Recommendation 1 of 2" and "Recommendation 2 of
2" — that's confusing.

**Impact:** Without UI distinction, reviewers see what looks like duplicate
recommendations.

**Fix path (UI):** Render remediations with citation-source-aware labels:
- OSV-cited remediation: "Authoritative fix (OSV registry)"
- LLM_INFERENCE-cited remediation: "Context-aware recommendation (analyzed
  for your use_case)"

Show citation badges (color-coded) to make the distinction immediately
visual. The CITATION SOURCE BADGES guide in the original UI spec already
defines these colors.

**Fix path (alternative — backend dedup):** If both remediations have the
same `type` AND `target_version`, collapse them into one with combined
citations. v1.1+.

---

## P3 — Documented behavior / won't fix

_(none open)_

---

## Smoke Test Results (2026-05-17 evening)

Performed against tag `v1.0-backend-complete` / commit `83f2dcf` /
175 tests passing. Environment: uvicorn booted from `.demo-venv` with
`PATH` extended to include the venv's `bin/` (so SBOMNode's
`pipdeptree` / `pip-licenses` subprocess calls resolve). `.env` at
project root has `ANTHROPIC_API_KEY=` (empty value in this
environment — LLM-related failures below are environmental, NOT code
defects; production has a real key).

Three previously-untested input paths exercised end-to-end via curl.

### Test 1: requirements_file upload path (saas)
- **Input:** base64-encoded `demo_requirements.txt` as `input_value`,
  `input_type="requirements_file"`, `use_case="saas"`.
  Job `job-6f1b8db0-7791-4a0f-b529-5d6783c3eafd`.
- **Result:** **PASS** for the scan itself, **FAIL** for the decision
  flow downstream of the first POST.
- Scan completed to `awaiting_human` in ~9s (warm caches). 151
  packages, 113 findings (5 crit / 27 high / 66 med / 15 low).
  Citation integrity audit: 0 findings without citations, 0
  malformed citations across all 113 entries.
- Decision flow: target finding propagates correctly to
  `cve_findings` (status="accepted", decided_by stamped) ✓
- BUT: audit chain sealed prematurely after the first decision; 41
  findings remain at `human_review` while `status="complete"`. See
  P0 above.
- **Recommended action:** Apply the `audit_node` `defer=True` fix
  before public deploy. Without it, the HITL demo arc is broken.

### Test 2: use_case=internal (verify policy threading)
- **Input:** same demo_requirements.txt, but
  `use_case="internal"`. Job `job-e2124e2e-38a8-49f4-9984-a01d27891a77`.
- **Result:** **DEGRADED**.
- Scan completed. Same 151 packages, 113 findings, IDENTICAL severity
  mix (5 crit / 27 high / 66 med / 15 low) to the SaaS run.
- `text-unidecode==1.3` (GPL-2.0) and `odfpy==1.4.1` (GPL-2.0) both
  tagged as `license_violation` + `severity=critical` regardless of
  `use_case=internal`. For an internal/non-distributed deployment,
  copyleft obligations don't trigger — the contract in DESIGN.md
  promises these should downgrade.
- Contextualization step: 30/30 LLM calls failed (env API key
  empty in smoke-test environment, see top-of-file note), so we
  can't verify whether the use_case STRING reaches the LLM prompts.
  The audit event payload confirms the contextualization step ran
  and failed defensively, but didn't crash.
- **Recommended action:** P1 follow-up — file a regression test that
  asserts use_case=internal downgrades GPL findings in the
  deterministic blocked-license path (LicenseNode), independent of
  the LLM contextualization. Production env should be re-tested with
  a real API key to verify use_case is in the LLM prompt.

### Test 3: repo_url ingestion
- **Input:** `input_type="repo_url"`,
  `input_value="https://github.com/Kaden-G/lablab-prep"`,
  `use_case="saas"`. Job `job-5493925b-519d-4a81-9564-7da60d9d9c88`.
- **Result:** **FAIL** (misleading rather than crashing).
- Did NOT hang or crash. Did NOT clone the repo. Returned 151
  packages — the server's running venv, identical to Test 1 + Test 2.
- Error surfaced in `state["errors"]`:
  `"repo_url path is a v1 stub: dependencies are read from the
   running venv"`.
- Dashboard doesn't expose repo_url input, so dashboard demo is
  unaffected. But API users get plausibly-wrong results. See P0
  above for the full reproduction and recommended action.
- **Recommended action:** P0 follow-up — either reject `repo_url`
  at the API layer or implement minimum-viable cloning before public
  deploy. Add a v1.1 note to the README/writeup either way.

### Other findings surfaced during smoke testing

**P2 — LangGraph deprecation warnings for unregistered msgpack types.**
On every scan resume, uvicorn logs warn that `agent_state.RiskLevel`,
`agent_state.CitationSource`, `agent_state.DecisionStatus`, and
`agent_state.RemediationType` are deserializing from checkpoint as
unregistered types. "This will be blocked in a future version."
Fix: register the four enum types with LangGraph's msgpack codec or
add them to `allowed_msgpack_modules`. Not breaking today, but
breaks "soon."

**P2 — License normalizer misses real-world license string formats.**
Production scan against the demo venv produces `license_unknown`
findings for several packages whose license strings aren't in the
SPDX map:
- `cvss==3.6`: `"GNU Lesser General Public License v3 or later (LGPLv3+)"`
- `orjson==3.11.9`: `"MPL-2.0 AND (Apache-2.0 OR MIT)"`
- `ormsgpack==1.12.2`: `"Apache-2.0 OR MIT"`
- `paramiko==2.12.0`: `"GNU Library or Lesser General Public License (LGPL)"`

The "OR" / "AND" multi-license syntax is real (PEP 639). The
GNU-prose variants are common in older packages. Currently these
get inflated to `license_unknown` (medium severity) and routed to
human review, padding the review queue. Fix in
`nodes/license_node.py`'s normalizer — add a few regex passes.
Estimated effort: 60 min.

**P2 — Optional data files referenced but missing on this machine.**
Errors:
- `SPDX dataset not found at /Users/kadengodinez/.../data/spdx_licenses.json; continuing without it`
- `Curated alternatives mapping not found at /Users/kadengodinez/.../data/curated_mappings.json; continuing without it`

Findings still get generated using fallback paths. Adding the data
files (or vendoring them in the repo) would let LicenseNode produce
SPDX-cited license findings instead of falling back to PYPI-only
citations. P2 polish for the citation integrity story.

### Summary

- **Path 1 (requirements_file via API):** scan path works, decision
  resume is broken (P0).
- **Path 2 (use_case=internal):** scan completes but severity is
  identical to SaaS — use_case isn't shaping deterministic license
  severity (P1).
- **Path 3 (repo_url):** silently returns server's venv as if it
  were the requested repo (P0, mitigated by the dashboard not
  exposing it).

**Pre-deploy gate:** at minimum, address Audit-Node-Defer (P0). The
repo_url case is mitigated by the dashboard NOT exposing the
endpoint — but if any external demo touches the API directly,
reject `repo_url` at the validation layer.

**Update 2026-05-18:** Both P0s resolved (commits `f240469`,
`c285613`). See PRE-DEPLOY ALERT at the top of this file. 178 tests
green.

---

## ✅ USE_CASE INVESTIGATION — 2026-05-18 (RESOLVED)

**Status:** **RESOLVED** by Design 1 — per-use_case policy schema.
Pre-fix state tagged `v1.0-design1-pre`. Fix in the commit
immediately following this update.

**What changed:**
- `POLICY.yml`: `licenses.blocked` is now a dict keyed by use_case
  (`saas`, `internal`, `distributed_binary`). `internal` is empty by
  design — non-distributed deployments don't trigger copyleft.
- `nodes/license_node.py`: new `_blocked_for_use_case()` helper dispatches
  on `isinstance(blocked, dict)`. Legacy flat-list policies still work
  as a universal block (backward compat path is tested).
- Policy citation identifier on blocked findings now includes the
  use_case path — `policy.licenses.blocked.{use_case}[{license_id}]` —
  so auditors can trace the exact rule that fired.
- Description text on blocked findings now references the use_case
  explicitly: "Your declared use_case='saas' blocks this license per
  organization policy. Copyleft / distribution obligations under this
  license are likely to apply to your deployment model."
- `input_node.py` SAFE_DEFAULTS mirrors the new schema; the input_node
  test was updated to assert on the dict shape.
- 15 new tests added in `tests/test_license_node.py`:
  - GPL-3.0 / AGPL-3.0 across all three use_cases (CRITICAL for
    saas + distributed, NOT-CRITICAL for internal)
  - LGPL-3.0 across all three (CRITICAL for distributed_binary only;
    saas/internal fall through to LLM)
  - MIT under all three (no finding)
  - Citation identifier includes the use_case path
  - Citation identifier distinguishes use_cases (same license,
    different identifiers)
  - Legacy flat-list policies still trigger CRITICAL under all
    use_cases (backward compat)

**Audit trail story:** the policy_hash recomputation triggered by
the POLICY.yml restructure forces a clean L2 memo re-evaluation,
which is the intended behavior — prior decisions encoded under the
old schema shouldn't transparently apply to the new one.

Original analysis preserved below for posterity.

---

## USE_CASE INVESTIGATION — 2026-05-18 (original analysis)

Scoping report for the P1 from the smoke test:
> "use_case=internal does NOT downgrade GPL findings in LicenseNode.
> text-unidecode (GPL-2.0) + odfpy (GPL-2.0) stay CRITICAL violations
> under both saas and internal. Severity counts are byte-for-byte
> identical between the two scans."

**Discovery only — no code changes in this session.**

### Verdict: **Reality B with a nuance.**

use_case IS plumbed all the way through LicenseNode and DOES reach
the LLM prompt for the gray-area / requires_review path. **But the
specific code path that produces the CRITICAL findings on GPL/AGPL
packages (the `policy.licenses.blocked` fast-path) bypasses use_case
entirely and hardcodes `RiskLevel.CRITICAL`.** It's not a missing
LLM branch — it's a policy-design choice in POLICY.yml combined
with a hardcoded severity in `_evaluate_blocked()`.

### Evidence

**1. `use_case` IS threaded through every LicenseNode helper.**
`grep -c use_case nodes/license_node.py` returns 24 matches. It's
on every `_evaluate_*` function signature, threaded into the
`_make_finding(...)` factory as a stamped field, and is the second
positional argument to `_call_llm_for_license_reasoning()`.

**2. `use_case` IS in the LLM prompt.**
`nodes/license_node.py:227-249` (`LLM_PROMPT_TEMPLATE`):
```text
The organization's declared use case is: {use_case}
...
1. Is this license compatible with the {use_case} use case? (yes/no/conditional)
```
So for LGPL-3.0 / MPL-2.0 / CDDL-1.0 / EPL / EUPL findings — the
ones on the `licenses.requires_review` list — use_case genuinely
shapes the verdict.

**3. The blocked-license fast-path skips the LLM AND hardcodes
CRITICAL.** `nodes/license_node.py:331-380` `_evaluate_blocked()`:
```python
def _evaluate_blocked(pkg, license_id, use_case, spdx_dataset, curated):
    ...
    return _make_finding(
        pkg,
        finding_type="license_violation",
        severity=RiskLevel.CRITICAL,   # ← hardcoded, ignores use_case
        description=(
            f"{license_id} detected. Use case {use_case!r} is incompatible "
            f"with this license per organization policy."   # ← description LIES for internal
        ),
        ...
    )
```
For `use_case=internal`, the description text says the use case is
"incompatible with this license per organization policy" — but the
copyleft obligations of GPL only trigger on distribution. For
internal/non-distributed deployments, GPL is generally permissible.
The severity stays CRITICAL anyway because the function doesn't read
use_case for the severity decision.

**4. POLICY.yml encodes this as a deliberate policy.**
`POLICY.yml:127-139`:
```yaml
# Licenses explicitly blocked regardless of use_case.
# Findings for packages with these licenses are always CRITICAL severity
# and always route to HUMAN_REVIEW. No auto-remediation.
blocked:
  - "GPL-2.0-only"
  - "GPL-2.0-or-later"
  - "GPL-3.0-only"
  - "GPL-3.0-or-later"
  - "AGPL-3.0-only"
  - "AGPL-3.0-or-later"
  ...
```
The comment "regardless of use_case" + "always CRITICAL" matches
LicenseNode's behavior exactly. So the LicenseNode code is
faithful to the policy file — the bug is in the policy design,
not in the implementation.

**5. There is no existing per-use_case override mechanism.**
POLICY.yml's `licenses:` section has three flat lists (`allowed`,
`blocked`, `requires_review`) and an `unknown_license_action`
scalar. None of these key on use_case. `policy_overrides` (the
field hashed into policy_hash for L2 memoization) is a top-level
override but operates at the same flat-list granularity.

### Two viable fixes (NOT applied — pick before scheduling)

**Design 1 — Per-use_case blocked lists in POLICY.yml (more
correct, more invasive).**
Restructure `licenses.blocked` from a flat list into either a dict
keyed by use_case:
```yaml
licenses:
  blocked:
    saas:               [GPL-2.0-only, GPL-3.0-only, AGPL-3.0-only, ...]
    internal:           [AGPL-3.0-only]   # AGPL still triggers via network
    distributed_binary: [GPL-2.0-only, GPL-3.0-only, AGPL-3.0-only, ...]
```
or a parallel `blocked_for_use_case` mapping. Modify
`_evaluate_license()` to look up the current use_case before
dispatching to `_evaluate_blocked()`. For `internal`, GPL would
fall through to the LLM-reasoning path which already takes
use_case into account, producing a context-aware verdict.

Estimated effort:
- POLICY.yml restructure + backward-compat parsing: ~1h
- LicenseNode dispatch update: ~30min
- New tests (per-use_case blocking behavior, AGPL-stays-blocked-for-saas
  invariant): ~1h
- Documentation in POLICY.yml comments + DESIGN.md: ~30min
- **Total: ~3h**

**Design 2 — Severity downgrade for use_case=internal in
_evaluate_blocked() (cheaper, more brittle).**
Keep `licenses.blocked` flat. In `_evaluate_blocked()`, after the
fast-path matches, check `if use_case == "internal" and license_id
in COPYLEFT_INTERNAL_OK_SET: ...` and downgrade severity to
MEDIUM with `finding_type="license_restricted"`. Hardcoded list
of copyleft-distribution-only licenses lives in license_node.py.

Estimated effort:
- LicenseNode logic: ~20min
- Tests: ~30min
- DESIGN.md note: ~10min
- **Total: ~1h**

### Recommendation

**Design 1** if there's time before the demo. It's the
policy-driven approach the comment block in POLICY.yml implies
should exist, and it generalizes — e.g. for `distributed_binary`,
LGPL might need stricter treatment than for `saas`. The L2
memoization key already includes `policy_hash`, so restructuring
the policy bumps the hash and forces a clean re-evaluation
(intentional).

**Design 2** if shipping today and the policy structure work is
out of scope. Add a TODO in license_node.py pointing at this
section.

### Out of scope for this investigation

- The CVE contextualization path uses a separate LLM prompt
  (`nodes/risk_node.py::_call_llm_for_cve_context`) that ALSO
  receives `use_case`. The smoke test couldn't verify whether the
  use_case STRING reaches that prompt because the .env in the
  smoke environment had `ANTHROPIC_API_KEY=` (empty). Production
  needs a re-run with a real key to confirm the CVE side, but the
  source code threading looks correct.
- The "the description text lies for internal" wording bug (point
  3 above) is a P2 cosmetic regardless of which design wins. Flag
  it for follow-up.
