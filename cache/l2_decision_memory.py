"""
cache/l2_decision_memory.py
============================
L2 Decision Memory — in-memory, keyed by compliance context tuple.

Stores prior human decisions so reviewers don't re-litigate findings
they've already resolved. This is one of SignedOff's key UX differentiators
vs. passive scanners — enterprise compliance teams hate making the same
decision twice.

Key:   "{package}:{version}:{finding_type}:{use_case}:{policy_hash}"
       e.g. "django:4.2.3:cve:saas:sha256:a1b2c3..."

Value: the full prior decision record (see store() docstring)

CRITICAL DESIGN INVARIANT:
    The policy_hash component means a policy change AUTOMATICALLY
    invalidates all prior L2 hits for affected findings. If the org
    updates POLICY.yml (e.g. adds GPL to blocked list), the new
    policy_hash produces different keys → prior decisions don't carry
    forward silently.

    This is not a bug, it's the feature. Policy drift should not
    silently inherit old decisions made under different rules.
    "We accepted this under the old policy" is a human decision
    to make, not an automatic one.

TTL: None for v1. Prior human decisions are audit artifacts — they
     don't expire. v2: add optional TTL per severity level.

Thread safety: single-process, async — no locking needed for v1.

L2 modes (from POLICY.yml prior_decisions section):
    always_resurface      → finding is shown fresh, must re-review
    show_for_confirmation → one-click confirm or re-review
    auto_accept_with_log  → auto-applied, audit-logged, never silent
"""

from datetime import datetime, timezone
from typing import Optional


class L2DecisionMemory:
    """
    In-memory L2 decision memory for prior human compliance decisions.

    Lifecycle:
        - RiskNode checks L2 before routing findings to HUMAN_REVIEW
        - DecisionGateNode writes to L2 after human resolves a finding
        - Memory persists for the lifetime of the process (v1)
        - v2: persist to database for cross-session memory
    """

    def __init__(self):
        self._store: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Cache key
    # ------------------------------------------------------------------

    @staticmethod
    def make_key(
        package: str,
        version: str,
        finding_type: str,
        use_case: str,
        policy_hash: str,
    ) -> str:
        """
        Canonical L2 memory key.

        All five components are required. Changing ANY component
        produces a different key — prior decisions don't carry forward
        across use_case or policy changes.

        Component design rationale:
            package + version:  identifies what was reviewed
            finding_type:       "cve" and "license_violation" for the same
                                package are different decisions
            use_case:           GPL is fine for "internal", lethal for "saas"
                                — a use_case change must force re-review
            policy_hash:        policy change invalidates all prior decisions
                                made under the old policy rules

        >>> L2DecisionMemory.make_key(
        ...     "django", "4.2.3", "cve", "saas", "sha256:abc123"
        ... )
        'django:4.2.3:cve:saas:sha256:abc123'
        """
        return f"{package}:{version}:{finding_type}:{use_case}:{policy_hash}"

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(
        self,
        package: str,
        version: str,
        finding_type: str,
        use_case: str,
        policy_hash: str,
    ) -> Optional[dict]:
        """
        Look up a prior decision for this exact compliance context.

        Returns the prior decision record if found, None if no prior
        decision exists (or if policy/use_case has changed since then).

        Usage in RiskNode:
            prior = l2_memory.get(
                finding["package"], finding["version"],
                finding["finding_type"], use_case, policy_hash
            )
            if prior:
                finding["prior_decision"] = prior
                l2_mode = policy["prior_decisions"][severity]["mode"]
                if l2_mode == "auto_accept_with_log":
                    finding["decision_status"] = DecisionStatus.ACCEPTED
                    finding["decided_by"] = "auto_l2"
                # For other modes: leave as HUMAN_REVIEW,
                # UI surfaces prior_decision for the reviewer
        """
        key = self.make_key(package, version, finding_type, use_case, policy_hash)
        return self._store.get(key)

    def has(
        self,
        package: str,
        version: str,
        finding_type: str,
        use_case: str,
        policy_hash: str,
    ) -> bool:
        """Check existence without retrieving the full record."""
        key = self.make_key(package, version, finding_type, use_case, policy_hash)
        return key in self._store

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def store(
        self,
        package: str,
        version: str,
        finding_type: str,
        use_case: str,
        policy_hash: str,
        decision_status: str,
        rationale: Optional[str],
        decided_by: str,
        finding_id: str,
        job_id: str,
    ) -> dict:
        """
        Record a human decision in L2 memory.

        Called by DecisionGateNode after a human resolves a finding.
        Only stores ACCEPTED and DEFERRED decisions — AUTO_REMEDIATE
        decisions don't need L2 memory because they're policy-driven
        and will be auto-resolved the same way next time regardless.

        Args:
            package:         Package name e.g. "django"
            version:         Package version e.g. "4.2.3"
            finding_type:    e.g. "cve", "license_violation"
            use_case:        Declared use case at time of decision
            policy_hash:     SHA-256 of POLICY.yml at time of decision
            decision_status: "accepted" | "deferred"
            rationale:       Human-provided rationale (required for
                             accepted/deferred — enforced upstream)
            decided_by:      User identifier e.g. "jane.doe@org.com"
            finding_id:      f-{uuid4} of the original finding
            job_id:          job-{uuid4} of the scan job

        Returns:
            The stored decision record (same shape as get() returns).
        """
        key = self.make_key(package, version, finding_type, use_case, policy_hash)

        record = {
            # Identity
            "package": package,
            "version": version,
            "finding_type": finding_type,
            "use_case": use_case,           # context at time of decision
            "policy_hash": policy_hash,     # policy at time of decision

            # Decision
            "decision_status": decision_status,
            "rationale": rationale,
            "decided_by": decided_by,
            "decided_at": datetime.now(timezone.utc).isoformat(),

            # Provenance — links back to the original scan
            "finding_id": finding_id,
            "job_id": job_id,
        }

        self._store[key] = record
        return record

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def get_all_for_package(self, package: str) -> list[dict]:
        """
        Retrieve all prior decisions for a given package name,
        regardless of version, finding_type, use_case, or policy.

        Useful for the "history" view in the UI — "show me all past
        decisions for django across all versions and scan contexts."
        """
        return [
            record for key, record in self._store.items()
            if key.startswith(f"{package}:")
        ]

    def get_all_for_job(self, job_id: str) -> list[dict]:
        """
        Retrieve all decisions made during a specific scan job.
        Useful for the audit trail — "what decisions were made in job X?"
        """
        return [
            record for record in self._store.values()
            if record.get("job_id") == job_id
        ]

    def size(self) -> int:
        """Total number of stored decisions."""
        return len(self._store)

    def clear(self) -> None:
        """Clear all stored decisions. Used in tests."""
        self._store.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# Imported by RiskNode (reads) and DecisionGateNode (writes).
# One memory instance per process lifetime.
# v2: replace with AsyncPostgresDecisionMemory backed by a decisions table.
# ---------------------------------------------------------------------------
l2_memory = L2DecisionMemory()
