# SignedOff

**An autonomous compliance officer for Python supply chains — not another scanner.**

SignedOff takes a `requirements.txt` and returns a policy-gated compliance verdict:
license risk, CVE exposure, and a human-in-the-loop review gate — every decision
sealed in a tamper-evident, hash-chained audit trail that verifies *without our
servers*.

🔗 **Live demo:** https://signedoff.onrender.com/ — scan your own `requirements.txt`,
no login, no data retention.

**Stack:** LangGraph · FastAPI · Anthropic Claude · OSV.dev · PyPI JSON API

---

## The problem

A typical Python application ships 500+ transitive dependencies. Manually reviewing
licenses and CVEs per release runs 200–500 engineer-hours per audit cycle — tens of
thousands of dollars of senior engineering labor, just to produce evidence.

Existing tools make this worse, not better: they flag everything, prioritize nothing,
and leave no audit trail. A SOC 2 or FedRAMP auditor doesn't ask "did you scan it?" —
they ask "show me the defensible evidence." The gap between a dashboard and an
audit-ready paper trail is where enterprise deals stall.

SignedOff closes that gap.

---

## What it does

Six stages, from `requirements.txt` to an audit-ready verdict — every decision
traceable, every claim cited.

| # | Stage | What happens |
|---|-------|--------------|
| 1 | **Resolve** | Parses direct + transitive packages; fetches license metadata from the PyPI JSON API. |
| 2 | **Classify** | License and CVE evaluated *in parallel*; CVE data pulled from OSV.dev. GPL in SaaS ≠ GPL in a distributed binary. |
| 3 | **Score** | License risk and security risk computed *independently* — never fused into a single misleading number. |
| 4 | **Decide** | Routes by `POLICY.yml`: auto-accept, auto-remediate, or escalate to human review. Weak citations always escalate. |
| 5 | **Sign** | Every decision sealed into a SHA-256 hash-chained audit log. |
| 6 | **Report** | Final report with full citation trail, ready for auditor handoff. |

---

## What makes it different

**Citation integrity — no hallucinated CVEs.** The LLM *interprets* evidence; it
never *generates* it. Every CVE citation traces to an OSV.dev record with a
`content_hash` for tamper detection. This removes the model from the
legal/compliance critical path entirely — and it means a foundation-model provider
shipping a new feature can't erode the moat. The value lives in the data sources and
the policy engine, not in the model.

**A hash-chained audit trail.** Every node event, policy decision, and human
override is recorded in a SHA-256 hash chain that seals only after all in-flight
decisions resolve. Tamper with any record and the chain breaks. Verifiable offline,
without SignedOff's servers — `GET /audit/verify/{job_id}`. Other scanners show an
auditor a dashboard; SignedOff shows them cryptographic proof.

**Use-case-aware policy.** The same dependency carries different obligations under
different deployment models. `POLICY.yml` declares the organization's tolerance per
use-case (`saas`, `internal`, `distributed_binary`) — eliminating the
"depends-which-reviewer-was-on-Friday" inconsistency auditors flag.

**Two-dimensional risk.** License risk and security risk are surfaced separately.
A lawyer and a security lead read the same dashboard and each get the answer they
actually need.

---

## Architecture

SignedOff is a LangGraph state machine. Graph topology lives in one file
(`graph.py`); node implementations live in `nodes/*.py`.

```
InputNode → SBOMNode → ┬─ LicenseNode ─┐
                       └─ CVENode ─────┘  (true parallel branch)
                                ↓
                            RiskNode      (fan-in: both branches complete)
                                ↓
                        DecisionGateNode ←→ [interrupt() / human review]
                                ↓
                  AutoRemediateNode / AutoAcceptNode
                                ↓
                            AuditNode     (seals the hash chain)
                                ↓
                            ReportNode
```

**Why the parallel branch is concurrency-safe:** `LicenseNode` writes only to
`license_findings`; `CVENode` writes only to `cve_findings`. Neither touches the
other's output field. The two fields they *do* share — `errors` and `audit_events` —
use `operator.add` reducers, making concurrent appends safe by construction. This is
LangGraph's native fan-out/fan-in, not hand-rolled threading.

See [`DESIGN.md`](DESIGN.md) for the full state schema, citation-integrity
guardrails, and L1/L2 caching architecture.

---

## Quick start

```bash
git clone https://github.com/Kaden-G/SignedOff.git
cd SignedOff

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

cp .env.example .env               # add ANTHROPIC_API_KEY=sk-ant-...
uvicorn api:app --reload
```

Open `http://localhost:8000` — the dashboard loads automatically.

---

## Tests

```bash
pytest -v        # 218 tests
```

End-to-end smoke test (server running, `ANTHROPIC_API_KEY` set):

```bash
python smoke_test.py    # standard scan, policy override, empty-input edge case
```

---

## Configuration

`POLICY.yml` is the organization's declarative risk-tolerance contract — edit
thresholds without touching code:

```yaml
licenses:
  blocked:
    saas:               [GPL-2.0, GPL-3.0, AGPL-3.0]
    internal:           []
    distributed_binary: [GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-2.1, LGPL-3.0]
cve:
  block_severity: CRITICAL
  flag_severity:  HIGH
```

A SHA-256 hash of `POLICY.yml` is embedded in every cached decision — so a policy
change automatically invalidates prior cache hits and forces human re-review.

Secrets (`ANTHROPIC_API_KEY`) go in `.env`, never in `POLICY.yml`.

---

## API

Full HTTP surface in [`API_CONTRACT.md`](API_CONTRACT.md). Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan/start` | Submit a `requirements.txt` for scanning |
| `GET`  | `/scan/results/{job_id}` | Full package + finding list |
| `GET`  | `/scan/pending-review/{job_id}` | Findings awaiting human decision |
| `POST` | `/scan/decision/{finding_id}` | Submit accept/defer for a finding |
| `GET`  | `/audit/trail/{job_id}` | Hash-chained audit log |
| `GET`  | `/audit/verify/{job_id}` | Chain integrity verification |

---

## Built by

**Kaden Godinez** — engineering and architecture: the LangGraph agent pipeline,
parallel scanning branch, citation-integrity design, hash-chained audit trail, and
FastAPI service layer. Marine Corps veteran; M.S. Information Systems Engineering,
Johns Hopkins (Applied GenAI certificate).

**Erika Godinez** — compliance domain expertise and go-to-market framing: the
audit-driven enterprise buyer, procurement realities, and evidence demands SignedOff
is built to satisfy.

---

## Origin

SignedOff began as a submission to the lablab.ai "Transforming Enterprise Through AI"
hackathon (May 2026). It has since been developed further as a standalone project;
the roadmap toward multi-ecosystem support (npm, Maven, Go), persistent storage, and
auto-PR remediation is documented in [`DESIGN.md`](DESIGN.md).
