"""Tests for nodes.input_node."""

from __future__ import annotations

import asyncio
import base64
import sys
from pathlib import Path

# Make project root importable when running pytest from any directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from nodes import input_node as input_node_mod  # noqa: E402
from nodes.input_node import input_node  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _valid_state(**overrides) -> dict:
    state = {
        "job_id": "job-test-001",
        "input_type": "requirements_file",
        "input_value": base64.b64encode(b"requests==2.31.0\n").decode("ascii"),
        "use_case": "saas",
    }
    state.update(overrides)
    return state


def test_valid_requirements_file_runs_and_loads_policy():
    result = _run(input_node(_valid_state()))

    assert result["status"] == "running"
    assert isinstance(result["policy"], dict)
    assert "policy_hash" in result["policy"]
    # Real POLICY.yml exists in repo, so the hash is a SHA-256, not "defaults".
    assert result["policy"]["policy_hash"] != "defaults"
    assert len(result["policy"]["policy_hash"]) == 64
    assert result["errors"] == []

    events = result["audit_events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "scan_started"
    payload = events[0]["payload"]
    assert payload["job_id"] == "job-test-001"
    assert payload["use_case"] == "saas"
    assert payload["input_type"] == "requirements_file"
    assert payload["policy_hash"] == result["policy"]["policy_hash"]


def test_invalid_use_case_fails():
    result = _run(input_node(_valid_state(use_case="enterprise")))

    assert result["status"] == "failed"
    assert result["policy"] == {}
    assert any("use_case" in err for err in result["errors"])

    events = result["audit_events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "validation_failed"
    assert events[0]["payload"]["field"] == "use_case"


def test_missing_policy_yml_uses_safe_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr(
        input_node_mod, "POLICY_PATH", tmp_path / "no_such_policy.yml"
    )

    result = _run(input_node(_valid_state()))

    assert result["status"] == "running"
    assert result["policy"]["policy_hash"] == "defaults"
    # Safe defaults preserve the structure RiskNode expects. The
    # blocked field is a dict keyed by use_case under the post-Design-1
    # schema (2026-05-18); GPL-3.0 is blocked for the saas + distributed
    # use cases and absent from internal.
    assert "MIT" in result["policy"]["licenses"]["allowed"]
    blocked = result["policy"]["licenses"]["blocked"]
    assert isinstance(blocked, dict), (
        "SAFE_DEFAULTS.licenses.blocked should be a per-use_case dict"
    )
    assert "GPL-3.0-only" in blocked["saas"]
    assert "GPL-3.0-only" in blocked["distributed_binary"]
    assert blocked["internal"] == []

    assert len(result["errors"]) == 1
    assert "not found" in result["errors"][0].lower()

    events = result["audit_events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "scan_started"
    assert events[0]["payload"]["policy_hash"] == "defaults"


def test_malformed_base64_fails():
    result = _run(input_node(_valid_state(input_value="@@@not valid base64@@@")))

    assert result["status"] == "failed"
    assert result["policy"] == {}
    assert any("base64" in err.lower() for err in result["errors"])

    events = result["audit_events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "validation_failed"
    assert events[0]["payload"]["field"] == "input_value"
