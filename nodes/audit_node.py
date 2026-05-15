"""
nodes/audit_node.py
===================
Hash-chains the staging audit_events into a tamper-evident audit_trail.

AuditNode is the ONLY node that writes to `audit_trail`. Every other
node appends raw events to `audit_events`. This separation makes the
hash chain DETERMINISTIC regardless of parallel execution — the chain
is sealed in one pass, sorted by timestamp, at a single terminal
point in the graph.

HASH CHAIN INVARIANTS (must match audit/verify_chain.py exactly):
  - Genesis block: prev_hash = "0" * 64
  - entry_hash = SHA-256 over the entry dict EXCLUDING entry_hash
  - JSON serialization uses sort_keys=True and default=str so the
    encoding is deterministic across Python versions and across
    enum/datetime values that may appear in payloads.
  - Tampering with any past entry breaks all subsequent hashes.

AuditNode is also the ONLY node that flips status to "complete".
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from agent_state import AgentState


GENESIS_PREV_HASH = "0" * 64


class AuditChainWriter:
    """
    Builds a hash-chained audit trail one entry at a time.

    Use sort_keys=True so dict iteration order can never change the
    hash. Use default=str so any non-JSON-native values (enums, datetime)
    serialize deterministically — verify_chain MUST use the same flags.
    """

    def __init__(self) -> None:
        self._seq = 0
        self._prev_hash = GENESIS_PREV_HASH

    def seal_entry(self, raw_event: dict) -> dict:
        entry = {
            "seq": self._seq,
            "timestamp": raw_event["timestamp"],
            "event_type": raw_event["event_type"],
            "payload": raw_event["payload"],
            "prev_hash": self._prev_hash,
        }
        entry["entry_hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        self._prev_hash = entry["entry_hash"]
        self._seq += 1
        return entry


async def audit_node(state: AgentState) -> dict:
    raw_events: list[dict] = list(state.get("audit_events") or [])

    # Stable sort by timestamp. Parallel branches (LicenseNode + CVENode)
    # may emit events with very close timestamps; ties preserve the
    # original insertion order so the chain remains reproducible.
    sorted_events = sorted(raw_events, key=lambda e: e["timestamp"])

    writer = AuditChainWriter()
    chain: list[dict] = [writer.seal_entry(e) for e in sorted_events]

    # Terminal "audit_sealed" entry — marks the end of the chain and
    # captures the final hash preview for downstream UI / verification.
    final_hash_preview = chain[-1]["entry_hash"][:16] + "..." if chain else None
    terminal = writer.seal_entry({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "audit_sealed",
        "payload": {
            "job_id": state.get("job_id"),
            "total_entries": len(chain) + 1,
            "final_hash_preview": final_hash_preview,
            "use_case": state.get("use_case"),
        },
    })
    chain.append(terminal)

    return {
        "audit_trail": chain,    # operator.add appends to the (empty) prior list
        "status": "complete",    # AuditNode is the ONLY node that sets "complete"
        "audit_events": [],      # do not re-emit anything (avoid loops)
        "errors": [],
    }
