# DESIGN.md — PyPI Dependency Compliance Agent

> **Status:** Pre-build architecture document
> **Last updated:** May 6, 2026
> **Hackathon:** lablab.ai "Transforming Enterprise Through AI" (May 11–19, 2026)
> **Authors:** Kaden Godinez (backend/agents), Ashu Ravichander (UI/demo/presentation)

---

## Table of Contents

1. [Product Vision](#product-vision)
2. [The Problem](#the-problem)
3. [Differentiation & Moat](#differentiation--moat)
4. [Market Context](#market-context)
5. [Pipeline Architecture](#pipeline-architecture)
6. [The Four Wickets](#the-four-wickets)
7. [Technology Stack](#technology-stack)
8. [State Schema (AgentState)](#state-schema-agentstate)
9. [Citation Integrity Guardrails](#citation-integrity-guardrails)
10. [Memory Architecture](#memory-architecture)
11. [LangGraph Node Architecture](#langgraph-node-architecture)
12. [API Contract (Backend ↔ Frontend)](#api-contract-backend--frontend)
13. [Division of Labor](#division-of-labor)
14. [Scope: In vs. Out for v1](#scope-in-vs-out-for-v1)
15. [Performance & Scale Targets](#performance--scale-targets)
16. [Production Considerations (Roadmap)](#production-considerations-roadmap-not-v1-scope)
17. [Submission Requirements](#submission-requirements)
18. [Timeline](#timeline)
19. [Open Questions / TBD](#open-questions--tbd)

---

## Product Vision

An **autonomous compliance officer** for Python software supply chains. Given a repository or `requirements.txt`, the agent:

1. Resolves the full dependency tree (direct + transitive)
2. Checks every package's license against the user's declared use case
3. Identifies known security vulnerabilities (CVEs)
4. Generates contextualized risk scores accounting for use case
5. Routes findings through a policy-driven decision gate with human-in-the-loop review
6. Records every decision in a tamper-evident, citation-backed audit trail

**One-line pitch:** "It's not a scanner — it's an autonomous compliance officer with a tamper-evident paper trail."

---

## The Problem

Enterprise software teams face two intertwined dependency risks:

**License compliance:** Open source packages come with license terms. A GPL-licensed dependency buried 4 levels deep in a transitive tree can infect a SaaS product with copyleft obligations. Existing tools (FOSSA, Black Duck, Mend) detect licenses but don't reason about *use case fit* — the same license can be compliant or violating depending on whether you're shipping SaaS, internal tooling, or a distributed binary.

**Security vulnerabilities:** CVE data is noisy, stale, and context-free. Existing tools (Snyk, GitHub Dependabot) flag CVEs but don't prioritize by actual exploitability in the user's specific deployment. A CRITICAL CVE in a dev-only dependency that never touches production is low actual risk — but generic scanners can't tell the difference.

**The gap:** Existing tools are **passive dashboards**. They tell you what's wrong. They don't reason about your context, propose specific remediation paths, or maintain an audit-defensible decision trail. They generate noise. Compliance teams drown in findings without prioritization.

---

## Differentiation & Moat

### What we are NOT

- Not another SBOM scanner (CycloneDX, Syft, etc. already do this)
- Not another vulnerability database (OSV, NVD, GHSA already do this)
- Not another license detector (FOSSA, FOSSology already do this)
- Not a wrapper around an existing tool's API

### What we ARE (and what makes this defensible)

1. **Agentic remediation** — not just detection, but autonomous triage with structured remediation options (version bump, package swap, compensating control, accept-as-is)

2. **Use-case-aware contextualization** — the same finding has different actual risk depending on deployment model. We reason about this with the LLM.

3. **Policy-driven decision gates** — organizations declare their own risk tolerance via `POLICY.yml`. The agent applies the policy uniformly. No more inconsistent human judgment across reviewers.

4. **Hash-chained audit trail** — every decision (auto or human) is logged with cryptographic tamper evidence. SOC 2, FedRAMP, CMMC auditors love this; existing tools don't have it.

5. **Citation-backed claims** — every finding and remediation is backed by traceable, validated evidence. No hallucinated CVEs. No made-up package alternatives.

### The "Landlord Rule" Defense

> *"Most AI startups pay rent to the foundation model providers and to the data providers. This works until the landlord adds the feature."*

Our defense:
- **Foundation model:** abstracted via multi-provider interface (Claude/OpenAI). Not locked to one provider.
- **Vulnerability data:** OSV.dev is open-source and free. NVD is government-funded. We don't depend on Snyk/Mend/FOSSA APIs.
- **License data:** SPDX is an open standard with a downloadable static dataset.
- **Our actual moat:** the orchestration layer (LangGraph agents + decision gates + audit trail). That's our code, not anyone else's.

---

## Market Context

We are not entering an empty market. Several established tools touch parts of this problem space. Honest assessment of the landscape and where we genuinely differentiate:

### Competitive Landscape

| Tool | What they do well | What they don't do |
|---|---|---|
| **Snyk** ($-$$) | Dominant CVE scanner, broad ecosystem, opens PRs | License detection bolted on; no use-case reasoning; no policy-as-code; no tamper-evident audit |
| **GitHub Dependabot** (free) | CVE alerts + auto-PRs in GitHub-native workflow | No policy layer, no audit trail, no license focus, no contextualization |
| **FOSSA** ($$) | Strong license detection and reporting | Weak on use-case reasoning; security is secondary; passive dashboard |
| **Black Duck** ($$$) | Enterprise heavyweight, both license + security | Slow, expensive, dashboard-centric, generic risk scoring |
| **Mend (WhiteSource)** ($$) | Solid both dimensions, established enterprise presence | Generic policies, no agentic remediation, closed data sources |
| **JFrog Xray** ($$$) | License + security, strong if already on Artifactory | Tightly coupled to JFrog ecosystem |
| **Socket.dev** ($-$$) | Novel angle: supply chain attack detection (typosquatting, malicious packages) | Adjacent problem, not direct competitor |
| **Trivy / Grype** (free) | Solid CLI-based CVE scanning | No enterprise workflow, no policy, no audit trail |
| **FOSSology** (free) | Open source license scanning | License-only, no security, dated UX |

### Why a Customer Would Choose Us Over These

We are NOT trying to beat Snyk for the average startup. They have a 10x larger team and 100x more vulnerability research investment. We compete in a specific lane:

**Compliance-regulated organizations** that need:

1. **Audit-defensible decision trails.** Hash-chained, tamper-evident, citation-backed. SOC 2, FedRAMP, CMMC auditors ask "show me your evidence" — we have it. Snyk shows you a dashboard.

2. **Policy-as-code uniformity.** Distributed teams making consistent decisions based on a declarative `POLICY.yml`, not individual reviewer judgment. Required for orgs with ISSO/compliance officer roles.

3. **Use-case-aware contextualization.** A GPL-3.0 dep is fine in internal tooling, lethal in distributed binary. Same CVE has different actual risk in SaaS vs. air-gapped deployments. Generic CVSS scores don't capture this; existing tools punt this judgment to the human.

4. **Open, no vendor lock-in.** Built on OSV (open), SPDX (open), curated mappings (transparent). No proprietary vulnerability databases, no closed scoring algorithms. Auditors can verify our reasoning end-to-end.

5. **Citation integrity guarantees.** Every claim is sourced. Every source is timestamped and validated. NONE_FOUND is an explicit, visible state. No hallucinated CVEs, no made-up package alternatives. Critical for organizations where false data is itself a compliance failure.

6. **Two-dimensional risk presentation.** License risk and security risk shown side-by-side, never fused. Different decision-makers (legal vs. security) can engage with their own dimension without sifting through merged scores.

### Honest Caveats

- **Snyk could add hash-chained audit trails.** They won't, because their existing customers don't ask for it and it's not their core market. Classic incumbent disadvantage we're exploiting.
- **For startups doing rapid CI/CD with low compliance burden, Snyk or Dependabot is probably a better fit.** That's fine. We're not trying to win that segment.
- **For Fortune 500 orgs already deeply invested in Black Duck or JFrog, switching costs are real.** We're better positioned for greenfield deployments and orgs where current tools are generating unacceptable alert fatigue or audit gaps.

### Target Customer Profile

**Primary ICP (Ideal Customer Profile):**
- Defense contractors, federal agencies (TS/SCI environments)
- Fintech with SOC 2 / PCI DSS requirements
- Healthcare with HIPAA / HITRUST requirements
- Public companies with SOX compliance
- Any org where "show me your evidence" is a regular question from auditors

**Secondary ICP:**
- Mid-market regulated SaaS companies frustrated with Snyk's signal-to-noise ratio
- Open source-aligned orgs uncomfortable with closed vendor data

**Not a fit:**
- Early-stage startups with no compliance requirements
- Orgs deeply integrated into a single vendor's ecosystem (JFrog Artifactory + Xray, etc.)
- Orgs where dependency scanning is a checkbox, not an active workflow

---

## Pipeline Architecture

```
┌─────────────────┐
│  User Input     │
│  (repo / reqs)  │
└────────┬────────┘
         │
┌────────▼────────┐
│   InputNode     │  Validates input, loads POLICY.yml,
│                 │  declares use_case
└────────┬────────┘
         │
┌────────▼────────┐
│   SBOMNode      │  Resolves full dependency tree,
│                 │  checks L1 cache per package
└────────┬────────┘
    ┌────┴────┐
    │         │
┌───▼──┐ ┌───▼──┐
│Lic.  │ │ CVE  │  Run concurrently (async)
│ Node │ │ Node │  Both produce Findings with citations
└───┬──┘ └───┬──┘
    └────┬────┘
         │
┌────────▼────────┐
│   RiskNode      │  Contextualizes license + security risk
│                 │  separately. Routes to decision states.
│                 │  Checks L2 memory for prior decisions.
└────────┬────────┘
         │
    ┌────┼────┐
    │    │    │
┌───▼─┐ ┌▼──┐ ┌▼────┐
│Auto │ │HIT│ │Auto │
│Remed│ │L  │ │Acc. │
└───┬─┘ └┬──┘ └┬────┘
    │    │     │
    └────┼─────┘
         │
┌────────▼────────┐
│   AuditNode     │  Writes hash-chained audit trail
└────────┬────────┘
         │
┌────────▼────────┐
│   ReportNode    │  Generates final report + summary
└─────────────────┘
```

---

## The Four Wickets

### Wicket 1: SBOM Generation

**Goal:** Resolve the full dependency tree and produce a normalized package list.

**Tools used (orchestrated, not reinvented):**
- `pipdeptree` for tree resolution
- `pip-licenses` for license metadata
- CycloneDX format as standard SBOM output

**Lock file priority:** `poetry.lock` > `Pipfile.lock` > pinned `requirements.txt` > unpinned `requirements.txt`

**Hard edge case (v2 scope):** Packages with C extensions or optional dependencies that only resolve at install time. v1 flags these; v2 will support a sandbox install mode for accurate resolution.

### Wicket 2: License Compliance

**Goal:** Classify each package's license and determine compatibility with the user's declared use case.

**Approach:**
- Use `pip-licenses` for primary license metadata
- Fallback: check the package's GitHub repo for a LICENSE file when PyPI metadata is missing
- Use SPDX license identifiers as canonical format
- LLM reasons about license vs. use case compatibility (constrained to grounding data — see Citation Integrity Guardrails)

**Use cases supported (v1):**
- `saas` — software delivered as a service over network
- `internal` — internal tooling, never distributed
- `distributed_binary` — shipped to end users as installable package

**Recommendation engine:** When a license is incompatible, propose alternatives via a hybrid approach:
- Curated mapping (20-30 most common packages, manually verified)
- LLM inference fallback (flagged as low confidence, requires human review)

### Wicket 3: CVE / Vulnerability Mapping

**Goal:** Identify and contextually prioritize known vulnerabilities.

**Data sources (priority order):**
1. **OSV.dev** — primary, has a clean REST API and Python SDK
2. **GitHub Advisory Database** — secondary
3. **PyPI vulnerabilities endpoint** — tertiary
4. **NVD** — fallback (has known backlog issues)

**Value-add over raw `pip-audit`:**
- LLM reasons about exploitability in the user's specific use case
- Incorporates fix availability into prioritization
- Distinguishes between "needs immediate patch" and "monitor for upstream fix"

### Wicket 4: Risk Matrix + Decision Gate

**Goal:** Combine license and security findings into actionable risk decisions with human-in-the-loop review.

**Architectural principle: License risk and security risk are NEVER fused.** They're presented as parallel dimensions because:
- Different remediation paths
- Different decision-makers (legal/compliance vs. security)
- Different temporal urgency (long-term vs. immediate)
- Different audit lifetime (permanent vs. time-bounded)

**Risk matrix UI presentation:**

| Package | License Risk | Security Risk | Action |
|---|---|---|---|
| requests 2.28 | NONE | HIGH | Review CVE |
| somelib 1.0 | CRITICAL | NONE | Replace pkg |
| oldlib 0.9 | MEDIUM | MEDIUM | Two-track review |

**Decision routing (driven by `POLICY.yml`):**
- Severity below `auto_remediate_below` threshold → `AUTO_REMEDIATE`
- Severity below `auto_accept_below` threshold → `ACCEPTED`
- Everything else → `HUMAN_REVIEW`

**Auto-remediate is gated:** A finding with only `LLM_INFERENCE` or `NONE_FOUND` citations CANNOT be auto-remediated regardless of policy threshold. Always routes to `HUMAN_REVIEW`.

---

## Technology Stack

| Layer | Choice | Why |
|---|---|---|
| Agent orchestration | **LangGraph** | Conditional branching, agent-to-agent state, async support. Better fit than Prefect for this graph shape. |
| LLM provider | Multi-provider abstraction (Claude primary, OpenAI fallback) | Avoid foundation-model lock-in (Landlord Rule) |
| SBOM tooling | `pipdeptree`, `pip-licenses` | Mature, PyPA-maintained, well-documented |
| SBOM format | **CycloneDX** | Industry standard, machine-readable |
| Vulnerability data | **OSV.dev** primary, GHSA secondary | Open, free, current, has Python SDK |
| License data | **SPDX** static dataset | Open standard, machine-readable, no API dependency |
| Backend API | **FastAPI** | Async-native, OpenAPI auto-generation for Ashu's frontend |
| Frontend | **Lovable** (React) + Figma mockups | Ashu's tooling, ships fast |
| Deployment | TBD (Railway, Render, Fly.io, or HF Spaces) | Must be publicly accessible per lablab.ai requirements |
| State store | In-memory for v1, with cache layer | Sufficient for hackathon scope |

---

## State Schema (AgentState)

The full schema lives in `agent_state.py`. Key design decisions:

### Top-level structure (lifecycle order)

```
Input Layer       → job_id, input_type, input_value, use_case, policy
SBOM Layer        → raw_dependency_tree, packages
License + CVE     → license_findings, cve_findings  (concurrent)
Risk Layer        → risk_matrix, risk_summary
Decision Layer    → pending_human_review, resolved_findings
Audit Layer       → audit_trail (hash-chained, append-only)
Meta Layer        → errors, status
```

### Core types

**`PackageRecord`** — normalized record per (name, version) pair. Carries:
- License metadata + status
- Raw CVE list
- **`license_risk`** AND **`security_risk`** (separate, never fused)
- Cache provenance (`from_cache`, `cached_at`)
- `transitive` flag (direct vs. transitive dep)

**`Finding`** — one actionable issue per package. Carries:
- `finding_type` (license_violation, cve, etc.)
- `severity` (raw, before contextualization)
- `recommendation` (one-liner) + `remediations` (structured options)
- `citations` (REQUIRED, non-empty)
- `decision_status` lifecycle
- `prior_decision` (L2 memory hit)

**`Remediation`** — structured fix option. Types: `VERSION_BUMP`, `PACKAGE_SWAP`, `CONFIG_CHANGE`, `COMPENSATING_CONTROL`, `NO_FIX_AVAILABLE`, `ACCEPT_AS_IS`. Each carries its own citations.

**`Citation`** — evidence record. REQUIRED on every Finding and Remediation. Carries:
- `source` (OSV, NVD, SPDX, LLM_INFERENCE, NONE_FOUND, etc.)
- `url`, `identifier`, `excerpt`
- `retrieved_at` timestamp
- `confidence` (authoritative / reliable / inferred / none)
- `validated` boolean + `validation_method`
- `content_hash` (SHA-256 for tamper detection)

### Concurrency safety

Two fields use `Annotated[list, operator.add]` reducers so multiple nodes can safely append concurrently:
- `audit_trail` (multiple nodes log events)
- `errors` (parallel nodes may report non-fatal errors)

---

## Citation Integrity Guardrails

Hallucinated citations would be **catastrophic** for an enterprise compliance tool. The system enforces three layers of defense:

### Layer 1: Architectural — LLMs Don't Generate Citations Directly

- All authoritative citations come from API responses or static reference data
- Code FETCHES the evidence; LLM INTERPRETS it
- LLM_INFERENCE citations carry `url=None` — no field for the LLM to hallucinate a URL into

**Required LLM prompting pattern:**

```
❌ NEVER: "What CVEs affect requests==2.28.0?"
   (LLM may hallucinate from training data)

✅ ALWAYS: "Here is the OSV API response: [actual JSON].
   Summarize the vulnerabilities described in this response.
   Do not include any vulnerabilities not present in the input."
   (LLM constrained to grounding data we already verified)
```

### Layer 2: Validation — Verify Every Citation Before Acceptance

- URL liveness check (HTTP HEAD, 2xx required) for URL citations
- Identifier format check (regex patterns) for identifier citations
- Failed validations → citation marked `validated=False`, finding confidence downgraded automatically
- Failed validations are LOGGED in `errors`, not silently dropped

### Layer 3: Explicit Absence — NONE_FOUND

- Empty citation lists are NEVER allowed
- When no evidence is found, use a `NONE_FOUND` citation
- Forces absence of evidence to be a **positive signal** in the UI rather than ambiguous missing data
- Findings with only `NONE_FOUND` or `LLM_INFERENCE` citations:
  - Cannot be auto-remediated
  - Cannot display "high confidence"
  - Always route to `HUMAN_REVIEW`

### Tamper Detection (Two Independent Checks)

1. **Audit trail hash chain** — temporal integrity. Tampering with any past entry breaks all subsequent hashes.
2. **Citation `content_hash`** — content integrity. SHA-256 of canonical Citation serialization, computed once at creation, cross-referenced with the audit trail entry that recorded the Citation.

To hide tampering, an attacker would have to modify Citation in state, recompute its content_hash, modify the audit_trail entry that recorded the original creation, recompute that audit entry's hash, AND recompute every subsequent audit entry's hash. Practically infeasible.

---

## Memory Architecture

Three layers, each with a distinct purpose:

### L1: Package Cache

**Key:** `package_name + version`
**Stores:** license metadata, known CVEs, SPDX classification
**TTL:** 7 days (CVEs change)
**Purpose:** Latency reduction. Most packages are scanned repeatedly across runs.

### L2: Decision Memory

**Key:** `package + version + finding_type + use_case + policy_hash`
**Stores:** prior human decisions, accepted risks, rationale
**TTL:** None (this is an audit artifact)
**Purpose:** Honor prior decisions without forcing re-litigation, while preserving accountability.

**Critical design decision: L2 hits NEVER auto-resolve silently by default.** Silent auto-approval has a subtle but real failure mode — context drift. Just because someone accepted a risk on March 15 doesn't mean the circumstances still hold:

- Use case may have changed (was internal, now SaaS)
- The CVE may have been re-scored (was MEDIUM, now CRITICAL)
- A patch may now exist that didn't before
- Compensating controls may have been removed
- The original reviewer may no longer work there
- New related CVEs may stack with the original

To balance "don't make me re-litigate" with accountability, L2 behavior is configurable per severity in `POLICY.yml`:

```yaml
prior_decisions:
  critical:
    mode: "always_resurface"        # never auto-approve
  high:
    mode: "show_for_confirmation"   # one-click confirm
  medium:
    mode: "show_for_confirmation"
  low:
    mode: "auto_approve_with_log"   # silent, but audit-logged
```

**Three modes:**

1. **`always_resurface`** — prior decision is shown but treated as "must re-review." Reviewer must engage with the finding fresh. Default for CRITICAL severity.

2. **`show_for_confirmation`** — prior decision shown prominently with a "Confirm previous decision" one-click button. Reviewer can confirm in 2 seconds OR drill in if something feels off. Default for HIGH and MEDIUM.

3. **`auto_approve_with_log`** — silent re-application of prior decision. Logged to audit trail (the decision IS recorded, with reference to the original decision that authorized it) but doesn't surface to the reviewer. Reserved for LOW severity where the noise reduction is worth the reduced visibility.

The middle option is the magic. It honors the L2 memory promise (don't make me re-litigate everything) while preserving human accountability (you saw it, you confirmed, your name is on the audit trail).

**HITL gate UX when L2 hits:**

> *"This finding was reviewed on 2026-03-15 by Jane Doe. Decision: ACCEPTED. Rationale: 'Vulnerable code path not exposed to user input.' Policy unchanged since then.*
>
> *[Confirm previous decision]   [Re-review in detail]"*

That UX explicitly surfaces the original decision context AND gives the reviewer one-click confirmation. Audit trail records: "decision X reaffirmed by user Y at time Z, original decision A by user B."

### L3: Org Policy Store

**Key:** Per-organization
**Stores:** `POLICY.yml` parsed contents + derived rules
**Updated:** Manually, version-controlled
**Purpose:** Inject consistent policy context into every agent run

### Cache Invalidation (v2 scope)

For v1, every L1 entry is stamped with `cached_at` and `ttl_days`. The actual scheduler/invalidation logic is v2 — don't build now.

---

## LangGraph Node Architecture

### Node responsibilities

| Node | Reads from state | Writes to state | Notes |
|---|---|---|---|
| `InputNode` | (input args) | `job_id`, `input_type`, `input_value`, `use_case`, `policy`, `status` | Validates POLICY.yml, normalizes input |
| `SBOMNode` | input fields | `raw_dependency_tree`, `packages` | Checks L1 cache per package |
| `LicenseNode` | `packages`, `use_case`, `policy` | `license_findings`, updates `packages[*].license_status` | Async, parallel with CVENode |
| `CVENode` | `packages`, `use_case`, `policy` | `cve_findings`, updates `packages[*].cves` | Async, parallel with LicenseNode |
| `RiskNode` | `packages`, `license_findings`, `cve_findings`, `policy` | `risk_matrix`, `risk_summary`, sets `packages[*].license_risk` and `[*].security_risk`, routes to `pending_human_review` or `resolved_findings` | Checks L2 decision memory |
| `DecisionGateNode` | `pending_human_review` | Updates `resolved_findings` with human decisions | Pauses pipeline; LangGraph interrupt pattern |
| `AutoRemediateNode` | findings with `decision_status=AUTO_REMEDIATE` | Updates `resolved_findings` | v2 stretch goal: opens PRs |
| `AuditNode` | All resolved state | `audit_trail` (hash-chained appends) | Runs continuously, also at terminal events |
| `ReportNode` | All terminal state | Returns final report | Generates executive summary + full findings |

### Async opportunity

`LicenseNode` and `CVENode` run **concurrently** after SBOM resolves. That's where most of the latency lives.

---

## API Contract (Backend ↔ Frontend)

FastAPI exposes these endpoints for Ashu's Lovable frontend:

```
POST /scan/start
  Body: { input_type, input_value, use_case, policy }
  Returns: { job_id }

GET  /scan/status/{job_id}
  Returns: { status, progress, errors }
  Polled by frontend for real-time updates

GET  /scan/results/{job_id}
  Returns: full findings (SBOM, licenses, CVEs)

GET  /scan/risk-matrix/{job_id}
  Returns: risk matrix with parallel license + security dimensions

GET  /scan/pending-review/{job_id}
  Returns: findings awaiting human decision

POST /scan/decision/{finding_id}
  Body: { decision_status, rationale }
  Updates a finding's decision

GET  /audit/trail/{job_id}
  Returns: hash-chained audit log

GET  /audit/verify/{job_id}
  Returns: integrity check results (hash chain valid? content hashes match?)
```

Ashu mocks these in Figma/Lovable against fake data while Kaden builds the real implementations. Swap to live API on Day 4-5.

---

## Division of Labor

Established Day 1, no overlap:

| Kaden owns | Ashu owns |
|---|---|
| All LangGraph agent logic | Figma mockups (Day 1-2) |
| OSV / PyPI / SPDX integrations | Lovable frontend build (Day 3-5) |
| `POLICY.yml` schema | Dashboard polish + UX |
| `AgentState` schema | Demo video + presentation |
| Audit trail + HITL gate | Pitch deck |
| Backend FastAPI surface | Submission writeup |
| Cache layer | Cover image |
| Citation validation | Live demo presentation |

**Q&A on demo day:** Ashu takes business/product questions, Kaden takes technical questions.

---

## Scope: In vs. Out for v1

### IN (hackathon v1)

✅ PyPI ecosystem only (no npm, Maven, etc.)
✅ SBOM via `pipdeptree` orchestration
✅ License compliance via `pip-licenses` + SPDX + LLM reasoning
✅ CVE detection via OSV.dev
✅ Use-case-aware risk contextualization
✅ Separate license_risk + security_risk dimensions
✅ Structured remediations with citation backing
✅ Citation validation (URL liveness, format checks)
✅ NONE_FOUND explicit absence markers
✅ L1 package cache + L2 decision memory
✅ Hash-chained audit trail
✅ Citation content hashes
✅ POLICY.yml driven decision routing
✅ Human-in-the-loop gate via LangGraph interrupt
✅ FastAPI backend exposed for Lovable frontend
✅ Risk matrix dashboard (Ashu)
✅ Demo video + pitch deck + submission writeup

### STRETCH (if Day 7 polish time available)

🎯 Demo-curated cache (`demo_cache.json`) — pre-fetched data for the specific packages in our demo `requirements.txt`, enabling the cold-vs-warm scan demo moment without building production-grade pre-warming. See [Production Considerations](#production-considerations-roadmap-not-v1-scope) for details.

### OUT (v2+)

❌ Cache invalidation scheduler (just stamp `cached_at` for now)
❌ Sandbox install mode for hard edge case packages
❌ Auto-PR remediation (open PRs to bump versions)
❌ Multi-ecosystem support (npm, Maven, Go, etc.)
❌ Reachability analysis (does the vulnerable code path apply?)
❌ Static analysis to infer use case from codebase
❌ Persistent database (in-memory state for hackathon)
❌ Multi-tenant / org isolation
❌ SSO / RBAC for the dashboard
❌ Webhook integrations (Slack, Jira, etc.)

---

## Performance & Scale Targets

### Realistic Package Counts

| Project type | Direct deps | Total resolved (incl. transitive) |
|---|---|---|
| Tiny CLI tool | 3-5 | 20-50 |
| Small Flask/FastAPI app | 10-15 | 60-120 |
| Standard Django app | 20-30 | 100-200 |
| Data science / ML project | 15-25 | 150-300 |
| Modern AI/LLM app (LangChain) | 25-40 | 300-500+ |
| Large enterprise monorepo | 50-100+ | 500-1,500+ |

**Target for hackathon demo:** 80-150 packages with deliberately seeded license issues and known CVEs. Big enough to be impressive, small enough to finish in demo time.

### Latency Targets

**Cold scan (~300 packages, no cache):**

| Step | Target |
|---|---|
| SBOMNode (subprocess + normalize) | 3-5 sec |
| License checks (300 pkgs, semaphore=10) | 6-8 sec |
| CVE checks via OSV `/v1/querybatch` | 2-4 sec |
| RiskNode (LLM reasoning) | 5-15 sec |
| **Total cold scan** | **~20-35 sec** |

**Warm scan (same project, 80% L1 cache hit rate):**

| Step | Target |
|---|---|
| SBOMNode | 3-5 sec |
| License checks (60 uncached, semaphore=10) | 1-2 sec |
| CVE checks (60 uncached, batched) | ~1 sec |
| RiskNode | 5-15 sec |
| **Total warm scan** | **~10-25 sec** |

### Critical Optimizations

1. **OSV `/v1/querybatch` endpoint** — accepts up to 1,000 packages in one request. Without this, 300 packages = 300 serial API calls. Non-negotiable use.

2. **Semaphore-bounded concurrency** — cap concurrent API calls to 10-20 to avoid rate limits. Use `asyncio.Semaphore(10)` inside LicenseNode and CVENode fan-outs.

3. **L1 cache aggressively** — even 50% hit rate cuts API calls in half. Surface cache stats in UI ("84 of 312 packages served from cache") to make optimization visible.

### UI Implications

Cold scans take 20-35 seconds even with full optimization. Frontend needs:
- Package count progress: "127 of 312 packages analyzed"
- Phase indication: "Resolving dependencies → Checking licenses → Scanning for CVEs"
- Live cache hit counter: "84 packages served from cache"
- No bare spinners — always show what's happening

---

## Production Considerations (Roadmap, Not v1 Scope)

These are documented for narrative purposes — to signal in the demo that we understand what production looks like — without committing to building them in the hackathon window.

### Pre-warmed Package Cache (v3 production feature)

In production, pre-warm the L1 cache for the top 5,000 PyPI packages by download volume. Refreshed nightly via background job. Covers ~80% of dependencies in a typical project, so first-time scans hit cache hard for most users.

**Tiering:**
- **Tier 1:** Top 1,000 PyPI packages — pre-cached, refreshed nightly, never evicted
- **Tier 2:** Per-customer warmed cache — populated after first scan, refreshed weekly
- **Tier 3:** Just-in-time — fetched on demand, normal TTL

**Production positioning:** "Existing tools scan in real-time, hitting external APIs every time. Our pre-warmed cache means 90% of your scan completes against local data. Faster, more reliable when external APIs are down, and reduces dependency on third-party rate limits."

### Hackathon Stretch: Demo-Curated Cache (Day 7 polish, if time)

A lightweight version that gets the demo benefit without the production complexity:

- Ship a `demo_cache.json` containing pre-fetched data for the specific 80-150 packages in our demo `requirements.txt`
- Load at startup, populate L1 cache from it
- Enables the cold-vs-warm demo moment without building real pre-warming infrastructure

**Cost:** 2-3 hours on Day 6-7. Cut if behind schedule.

**Demo framing (honest):** *"For this demo we've pre-cached the packages in this sample project. In production this same mechanism would pre-cache the top 5,000 packages on PyPI, refreshed nightly."*

### Other Production Items (Roadmap Only)

- **Persistent state store** — replace in-memory state with PostgreSQL for production
- **Multi-tenancy** — org isolation, per-org policy stores, per-org audit trails
- **SSO / RBAC** — enterprise auth integration (SAML, OIDC)
- **Observability** — OpenTelemetry traces, Prometheus metrics, structured logging
- **Webhook integrations** — Slack notifications, Jira ticket creation, GitHub PR comments
- **Auto-PR remediation** — actually open PRs to bump versions for AUTO_REMEDIATE findings
- **Sandbox install mode** — for packages with C extensions / dynamic deps
- **Multi-ecosystem support** — npm, Maven, Go modules, NuGet

---

## Submission Requirements

Per lablab.ai documentation:

**Required deliverables:**
- Working prototype accessible online (publicly reachable URL)
- Video presentation (demo of the project)
- Pitch deck (slides)

**Submission form fields:**
- Title (max 50 characters)
- Short description (max 255 characters)
- Long description (minimum 100 words)
- Main tracks (select categories)
- Technologies (list everything used)
- Cover image (16:9 ratio recommended)
- Additional info (how it scales beyond hackathon)

**Track alignment:** Enterprise security challenge — *"Build AI systems that enterprise security teams can actually trust and deploy."*

---

## Timeline

| Date | Milestone |
|---|---|
| **May 6 (today)** | Architecture + schema design, repo scaffolding |
| **May 6-10** | Pre-build prep: validate APIs, design POLICY.yml, test fixtures, environment setup. **No submission code committed.** |
| **May 11** | Build window opens. Real implementation starts. |
| **May 11-12** | InputNode, SBOMNode, basic FastAPI scaffold. Ashu starts Figma mockups. |
| **May 13-14** | LicenseNode + CVENode (parallel async), citation validation. Ashu starts Lovable build. |
| **May 15-16** | RiskNode, decision gate, L1 cache, L2 memory. Ashu refines dashboard against real API. |
| **May 17** | **Real internal deadline.** AuditNode, hash chain, end-to-end integration. Demo video drafted. |
| **May 18** | Polish, dry runs, hybrid build day. Pitch deck finalized. |
| **May 19** | Demos & Awards at San Jose Convention Center. |

**Hard deadline mindset:** Treat May 17 as the actual deadline. May 18-19 is polish + rehearsal.

---

## Open Questions / TBD

- [ ] **POLICY.yml schema** — full structure not yet designed. Next session.
- [ ] **Project name** — candidates: DepGuard, PacketWatch, ChainAudit, others TBD
- [ ] **Deployment target** — Railway vs. Render vs. Fly.io vs. HF Spaces. Cost is $0 for hackathon scope; choose based on ease of FastAPI deployment.
- [ ] **Live demo confirmation** — will all teams demo or only finalists? (Pending Discord clarification)
- [ ] **Curated PACKAGE_SWAP mapping** — which 20-30 packages to include in v1 (likely focus on web frameworks, HTTP clients, ORM/DB, testing, common ML)
- [ ] **Submission title + short description** — pre-draft before May 11

---

## Reference: Files in This Project

| File | Purpose |
|---|---|
| `DESIGN.md` | This document — master architecture reference |
| `agent_state.py` | Full state schema (TypedDicts, enums, citations) |
| `policy_schema.yml` | (TBD) POLICY.yml structure + examples |
| `nodes/*.py` | (TBD) Individual LangGraph node implementations |
| `graph.py` | (TBD) LangGraph state graph definition |
| `api.py` | (TBD) FastAPI endpoints |
| `cache/*.py` | (TBD) L1 + L2 memory implementations |
| `audit/*.py` | (TBD) Hash chain + citation validation |
| `tests/*.py` | (TBD) Test fixtures with known CVEs and license issues |
| `README.md` | (TBD) Public-facing project README for submission |

---

*This document is the canonical reference for design decisions. When in doubt during implementation, this wins. Update as decisions evolve.*
