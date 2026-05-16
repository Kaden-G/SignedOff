# SignedOff

A LangGraph-based compliance agent that scans Python projects for license
and CVE risk, applies policy thresholds, and routes findings to either
auto-decision branches or a human-in-the-loop review gate. Every decision
is recorded in a tamper-evident hash-chained audit trail.

See `DESIGN.md` for the full architecture and `API_CONTRACT.md` for the
HTTP surface.

## Installation

```bash
git clone https://github.com/Kaden-G/lablab-prep.git
cd lablab-prep

python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

cp .env.example .env  # if present, otherwise create .env manually
# Set ANTHROPIC_API_KEY in .env
```

Run the test suite to confirm everything is wired up:

```bash
pytest -v
```

Start the API:

```bash
uvicorn api:app --reload
```

## Two-environment pattern

SignedOff uses two separate Python environments:

**Project environment** — runs the agent itself.
  Created from `requirements-dev.txt`. Contains FastAPI, LangGraph,
  Anthropic SDK, aiohttp, etc.

**Demo/target environment** — contains the packages being scanned.
  Created from `demo_requirements.txt` (or a real project's
  requirements.txt). SBOMNode introspects this venv via pipdeptree.

These should NOT be the same venv. The agent runs in environment A
and scans environment B. In production, environment B would be an
ephemeral sandbox container per scan.

For local development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
# Now run pytest, uvicorn, etc. from this venv

python -m venv .demo-venv
source .demo-venv/bin/activate
pip install -r demo_requirements.txt
# The agent (running in .venv) reads this venv via pipdeptree
```
