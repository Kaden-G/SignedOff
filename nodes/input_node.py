"""
input_node.py
=============
Entry point of the SignedOff compliance agent graph.

Reads raw user input from state, validates it, loads POLICY.yml, and
emits the scan_started audit event. On fatal validation failure, sets
status="failed", emits validation_failed, and returns immediately so
the router in graph.py short-circuits to END.

Pure I/O + validation. No LLM calls, no network. AuditNode is
responsible for hash-chaining the audit_events emitted here into the
final audit_trail.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import yaml

from agent_state import AgentState


VALID_USE_CASES: frozenset[str] = frozenset({"saas", "internal", "distributed_binary"})
VALID_INPUT_TYPES: frozenset[str] = frozenset({"requirements_file"})
# "repo_url" used to be valid here but the SBOMNode branch never actually
# cloned anything — it returned the running venv's packages as the scan
# result, which is misleading at best. The API layer's Pydantic Literal
# now rejects repo_url at the boundary; this frozenset is a
# defense-in-depth check for the rare case where state is constructed
# directly (e.g. via tests or future internal callers). Re-add when
# real repo-URL ingestion lands in v1.1.

# Project root is the parent of the nodes/ package — same directory as graph.py.
# Tests monkeypatch this module attribute to redirect the lookup.
POLICY_PATH: Path = Path(__file__).resolve().parent.parent / "POLICY.yml"


SAFE_DEFAULTS: dict = {
    "schema_version": "1.0",
    "scan_defaults": {"use_case": "saas", "include_transitive": True, "max_depth": None},
    "thresholds": {
        "license": {"auto_remediate_below": "medium", "auto_accept_below": "low"},
        "security": {"auto_remediate_below": "high", "auto_accept_below": "low"},
    },
    "licenses": {
        "allowed": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"],
        # Per-use_case blocked lists — see POLICY.yml comment block for
        # the rationale. internal is empty by design (no distribution =
        # no copyleft trigger).
        "blocked": {
            "saas": [
                "GPL-2.0-only", "GPL-2.0-or-later",
                "GPL-3.0-only", "GPL-3.0-or-later",
                "AGPL-3.0-only", "AGPL-3.0-or-later",
            ],
            "internal": [],
            "distributed_binary": [
                "GPL-2.0-only", "GPL-2.0-or-later",
                "GPL-3.0-only", "GPL-3.0-or-later",
                "AGPL-3.0-only", "AGPL-3.0-or-later",
                "LGPL-2.0-only", "LGPL-2.0-or-later",
                "LGPL-2.1-only", "LGPL-2.1-or-later",
                "LGPL-3.0-only", "LGPL-3.0-or-later",
            ],
        },
        "requires_review": ["LGPL-2.1-only", "LGPL-2.1-or-later", "MPL-2.0"],
        "unknown_license_action": "human_review",
    },
    "prior_decisions": {
        "critical": {"mode": "always_resurface"},
        "high": {"mode": "show_for_confirmation"},
        "medium": {"mode": "show_for_confirmation"},
        "low": {"mode": "auto_accept_with_log"},
    },
    "policy_hash": "defaults",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validation_failed_event(reason: str, field: str) -> dict:
    return {
        "timestamp": _now_iso(),
        "event_type": "validation_failed",
        "payload": {"reason": reason, "field": field},
    }


def _scan_started_event(job_id: str, use_case: str, input_type: str, policy_hash: str) -> dict:
    return {
        "timestamp": _now_iso(),
        "event_type": "scan_started",
        "payload": {
            "job_id": job_id,
            "use_case": use_case,
            "input_type": input_type,
            "policy_hash": policy_hash,
        },
    }


def _fail(reason: str, field: str) -> dict:
    return {
        "policy": {},
        "status": "failed",
        "audit_events": [_validation_failed_event(reason, field)],
        "errors": [reason],
    }


def _load_policy() -> tuple[dict, list[str], bool]:
    """
    Returns (policy, warnings, fatal).

    - Missing file: SAFE_DEFAULTS with a warning, fatal=False (continue).
    - Parse error or non-mapping root: empty dict, error in warnings, fatal=True.
    - Success: parsed policy with policy_hash injected, no warnings, fatal=False.
    """
    if not POLICY_PATH.exists():
        return (
            dict(SAFE_DEFAULTS),
            [f"POLICY.yml not found at {POLICY_PATH}; using safe defaults"],
            False,
        )

    try:
        raw_bytes = POLICY_PATH.read_bytes()
    except OSError as exc:
        return ({}, [f"POLICY.yml could not be read: {exc}"], True)

    try:
        parsed = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as exc:
        return ({}, [f"POLICY.yml parse error: {exc}"], True)

    if not isinstance(parsed, dict):
        return (
            {},
            [f"POLICY.yml root must be a mapping; got {type(parsed).__name__}"],
            True,
        )

    parsed["policy_hash"] = hashlib.sha256(raw_bytes).hexdigest()
    return parsed, [], False


async def input_node(state: AgentState) -> dict:
    job_id = state.get("job_id", "")
    input_type = state.get("input_type", "")
    input_value = state.get("input_value", "")
    use_case = state.get("use_case", "")

    if use_case not in VALID_USE_CASES:
        return _fail(
            f"use_case must be one of {sorted(VALID_USE_CASES)}; got {use_case!r}",
            "use_case",
        )

    if input_type not in VALID_INPUT_TYPES:
        return _fail(
            f"input_type must be one of {sorted(VALID_INPUT_TYPES)}; got {input_type!r}",
            "input_type",
        )

    if not isinstance(input_value, str) or not input_value:
        return _fail("input_value must be a non-empty string", "input_value")

    if input_type == "requirements_file":
        try:
            decoded = base64.b64decode(input_value, validate=True)
        except (binascii.Error, ValueError):
            return _fail("input_value is not valid base64", "input_value")

        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return _fail(
                "input_value base64 does not decode to UTF-8 text",
                "input_value",
            )

        if not text:
            return _fail("input_value decodes to empty content", "input_value")

    policy, warnings, fatal = _load_policy()
    if fatal:
        return {
            "policy": {},
            "status": "failed",
            "audit_events": [_validation_failed_event(warnings[0], "policy")],
            "errors": warnings,
        }

    return {
        "policy": policy,
        "status": "running",
        "audit_events": [
            _scan_started_event(job_id, use_case, input_type, policy["policy_hash"])
        ],
        "errors": warnings,
    }
