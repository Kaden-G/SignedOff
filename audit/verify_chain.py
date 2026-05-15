"""
audit/verify_chain.py
=====================
Standalone audit-trail verification utility.

NOT a graph node — called by GET /audit/verify/{job_id} to recompute
every entry hash from scratch and prove the chain hasn't been touched
since AuditNode sealed it.

Hashing convention MUST match AuditNode's writer:
  - All fields except entry_hash are included in the hashed input
  - JSON serialization uses sort_keys=True and default=str
    (default=str makes enum / datetime values deterministic strings)

Tampering with ANY past entry breaks the chain at that seq number,
because every subsequent entry's prev_hash references the corrupted
entry's hash.
"""

from __future__ import annotations

import hashlib
import json


GENESIS_PREV_HASH = "0" * 64


def _compute_entry_hash(entry: dict) -> str:
    """
    Recompute an entry's hash exactly the way AuditNode's writer did.
    Excludes entry_hash itself from the input.
    """
    check_entry = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(
        json.dumps(check_entry, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def verify_chain(audit_trail: list[dict]) -> dict:
    """
    Walk the chain checking both prev_hash linkage and per-entry hash
    integrity. Returns the first failure encountered (or PASS if clean).

    Returns:
        {
          "chain_valid": bool,
          "broken_at_seq": int | None,
          "entries_verified": int,
          "verdict": "PASS" | "FAIL",
        }
    """
    if not audit_trail:
        return {
            "chain_valid": True,
            "broken_at_seq": None,
            "entries_verified": 0,
            "verdict": "PASS",
        }

    expected_prev_hash = GENESIS_PREV_HASH
    entries_verified = 0

    for entry in audit_trail:
        # 1. The chain link: prev_hash must match the prior entry's hash.
        if entry.get("prev_hash") != expected_prev_hash:
            return {
                "chain_valid": False,
                "broken_at_seq": entry.get("seq", entries_verified),
                "entries_verified": entries_verified,
                "verdict": "FAIL",
            }

        # 2. The per-entry seal: stored entry_hash must match recomputation.
        stored_hash = entry.get("entry_hash")
        computed_hash = _compute_entry_hash(entry)
        if computed_hash != stored_hash:
            return {
                "chain_valid": False,
                "broken_at_seq": entry.get("seq", entries_verified),
                "entries_verified": entries_verified,
                "verdict": "FAIL",
            }

        expected_prev_hash = stored_hash
        entries_verified += 1

    return {
        "chain_valid": True,
        "broken_at_seq": None,
        "entries_verified": entries_verified,
        "verdict": "PASS",
    }
