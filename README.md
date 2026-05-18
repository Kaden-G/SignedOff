# SignedOff

A LangGraph-powered supply-chain compliance agent for Python projects. Upload a
`requirements.txt`, get back a policy-gated audit report covering license risk,
CVE exposure, and a human-in-the-loop review gate — all backed by a tamper-evident
hash-chained audit trail.

**Hackathon:** lablab.ai "Transforming Enterprise Through AI" (May 11–19, 2026)  
**Stack:** LangGraph · FastAPI · Anthropic Claude · PyPI JSON API · OSV

---

## What It Does

1. **SBOM resolution** — parses `requirements.txt` and fetches license metadata for
   every package directly from the PyPI JSON API (no local venv introspection).
2. **CVE enrichment** — queries the OSV database for known vulnerabilities on each
   package version; CVSS scores and summaries extracted from NVD aliases.
3. **Policy evaluation** — compares licenses and CVE severity against
   `POLICY.yml` thresholds (configurable per use-case: `saas`, `internal`,
   `distributed_binary`).
4. **LLM contextualization** — HIGH/CRITICAL CVE findings are enriched by Claude
   with use-case-aware remediation guidance and an `action_type` recommendation
   (`version_bump`, `accept_as_is`, `compensating_control`, `monitor`).
5. **HITL gate** — findings that exceed policy thresholds are routed to a human
   review queue (`interrupt()`). The dashboard presents each finding with a
   one-click accept/defer decision form.
6. **Audit trail** — every node event, policy decision, and human override is
   recorded in a SHA-256 hash-chained audit log that seals only after all
   in-flight decisions are resolved.

---

## Quick Start

```bash
git clone https://github.com/Kaden-G/lablab-prep.git
cd lablab-prep

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

cp .env.example .env             # or create .env manually
# Add to .env:
#   ANTHROPIC_API_KEY=sk-ant-...

uvicorn api:app --reload
```

Open `http://localhost:8000` — the dashboard loads automatically.

---

## Running Tests

```bash
pytest -v                        # 218 tests
```

---

## Configuration

**`POLICY.yml`** — edit thresholds without touching code:

```yaml
licenses:
  blocked:
    saas:              [GPL-2.0, GPL-3.0, AGPL-3.0]
    internal:          []
    distributed_binary: [GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-2.1, LGPL-3.0]

cve:
  block_severity:      CRITICAL
  flag_severity:       HIGH

use_cases:             [saas, internal, distributed_binary]
```

**`.env`** — secrets only:

```
ANTHROPIC_API_KEY=sk-ant-...
```

---

## API

See [`API_CONTRACT.md`](API_CONTRACT.md) for the full HTTP surface.

Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan/start` | Submit a `requirements.txt` for scanning |
| `GET`  | `/scan/status/{job_id}` | Poll scan progress |
| `GET`  | `/scan/results/{job_id}` | Full package + finding list |
| `GET`  | `/scan/risk-matrix/{job_id}` | Grouped/flat/pending-review views |
| `GET`  | `/scan/pending-review/{job_id}` | Findings awaiting human decision |
| `POST` | `/scan/decision/{finding_id}` | Submit accept/defer for a finding |
| `GET`  | `/audit/trail/{job_id}` | Hash-chained audit log |
| `GET`  | `/audit/verify/{job_id}` | Chain integrity verification |

---

## Architecture

See [`DESIGN.md`](DESIGN.md) for the full LangGraph node graph, state schema,
citation integrity design, and memory architecture.

```
InputNode → SBOMNode → LicenseNode → CVENode
                                        ↓
                                     RiskNode (deferred join)
                                        ↓
                               DecisionGateNode ←→ [interrupt / HITL]
                                        ↓
                          AutoRemediate / AutoAccept
                                        ↓
                                    AuditNode (deferred join)
                                        ↓
                                    ReportNode
```

---

## Smoke Test

With the server running and `ANTHROPIC_API_KEY` set:

```bash
python smoke_test.py
```

Runs three end-to-end paths: standard scan, policy override, and edge-case
empty requirements. Prints pass/fail for each assertion.
