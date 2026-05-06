✅ Safe to Do Right Now (May 6-10)
Architecture and design (not functional code):

✅ DESIGN.md — already done, this is documentation
✅ agent_state.py — this is a schema definition, not functional code. It's a contract, like a database schema. No logic, no I/O. Defensible as planning.
✅ POLICY.yml schema design (also a contract, not logic)
✅ API contract design (just shapes, not implementations)
✅ Repo scaffolding — empty directories, empty __init__.py files, pyproject.toml with dependencies listed

Environment and tooling prep:

✅ Create the GitHub repo
✅ Set up Python venv
✅ Install dependencies (pip install langgraph fastapi pip-licenses pipdeptree osv ...)
✅ Get API keys configured (Anthropic, etc.) in .env
✅ Test that OSV API works with a manual curl (just exploration, not committed code)
✅ Test that pipdeptree produces the output format you expect

Test fixtures (data, not logic):

✅ Create a sample requirements.txt with known CVEs and license issues
✅ Create a sample POLICY.yml for testing
✅ Save sample OSV API responses as JSON fixtures

Diagrams and planning:

✅ Architecture diagrams (mermaid, draw.io, etc.)
✅ Sequence diagrams of node interactions
✅ Sketches of UI mockups (concepts, not Lovable build)
