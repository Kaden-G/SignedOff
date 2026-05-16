"""
agent_state.py
==============
Central state schema for the PyPI Dependency Compliance Agent.

This file defines the SINGLE source of truth for all data flowing
through the LangGraph pipeline. Every node reads from and writes back
to this state object. Think of it as the shared whiteboard that all
agents look at and write on.

LangGraph passes this state dict between nodes automatically. You never
manually pass data between nodes — you just update state and the graph
handles routing.

Design principles:
    - Flat where possible: deeply nested state is hard to debug
    - Append-only for audit artifacts: use Annotated[list, operator.add]
      so concurrent nodes can't overwrite each other's writes
    - Explicit over implicit: every field has a comment explaining its
      purpose, source, and which node(s) own it
    - Cache-aware: every package record tracks whether it came from
      cache so the UI can surface latency savings
    - Policy-injected: POLICY.yml is parsed once at input and carried
      through state so no node re-reads the file


CITATION INTEGRITY GUARDRAILS
==============================
Hallucinated citations would be CATASTROPHIC for an enterprise
compliance tool — far worse than no citations at all. A made-up CVE
URL that an auditor clicks and finds 404 destroys trust in the entire
system instantly.

The system enforces these invariants to prevent hallucinated evidence:

1. LLMs NEVER generate URLs or identifiers directly. All authoritative
   citations come from API responses or static reference data:
     - OSV citations come from actual OSV.dev API responses
     - NVD citations come from actual NVD API responses
     - PyPI citations come from actual PyPI metadata
     - SPDX citations come from the static SPDX license list
     - CURATED_MAPPING citations come from our internal JSON file
   Code FETCHES the evidence; LLM INTERPRETS it. The LLM is never
   the source of a citation URL or identifier.

2. LLM_INFERENCE citations carry url=None — there is literally no
   field for the LLM to hallucinate a URL into. The LLM generates
   reasoning text only; code wraps it in a Citation with no URL.

3. Every URL citation must pass a liveness check (HTTP HEAD returns
   2xx) before acceptance. Failed liveness → citation marked
   validated=False, finding confidence downgraded automatically.

4. Empty citation lists are NEVER allowed. When no evidence is found,
   use an explicit NONE_FOUND citation. This makes absence a positive
   signal in the UI rather than an ambiguous missing field.

5. A Finding or Remediation backed only by NONE_FOUND or LLM_INFERENCE
   citations CANNOT:
     - Be auto-remediated (always routes to HUMAN_REVIEW)
     - Display "high confidence" in the UI
     - Be excluded from human review based on policy thresholds

6. Every Citation carries a retrieved_at timestamp so the audit trail
   captures what the source said AT THE TIME of the scan, even if the
   source later changes.

7. LLM PROMPTING PATTERN (architectural defense, enforced in node
   implementations not schema):
     ❌ NEVER: "What CVEs affect requests==2.28.0?"
        (LLM may hallucinate from training data)
     ✅ ALWAYS: "Here is the OSV API response: [actual JSON].
        Summarize the vulnerabilities described in this response.
        Do not include any vulnerabilities not present in the input."
        (LLM constrained to grounding data we already verified)
"""

from typing import TypedDict, Annotated, Optional
from enum import Enum
import operator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """
    Severity classification for both license and CVE findings.

    Using str mixin so these serialize cleanly to JSON without
    needing a custom encoder. LangGraph state must be serializable.

    Mapping guidance:
        CRITICAL  — CVE CVSS >= 9.0 OR license is GPL/AGPL in a
                    distributed/SaaS context (copyleft infection risk)
        HIGH      — CVE CVSS 7.0-8.9 OR license is LGPL with unclear
                    linking model
        MEDIUM    — CVE CVSS 4.0-6.9 OR license is unclear/missing
                    metadata
        LOW       — CVE CVSS < 4.0 OR license is permissive but with
                    minor attribution requirements
        NONE      — No finding. Package is clean.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class DecisionStatus(str, Enum):
    """
    Lifecycle status of an individual finding as it moves through
    the pipeline toward resolution.

    State machine:
        PENDING
            └── policy auto-routes to ──► AUTO_REMEDIATE
                                      ──► HUMAN_REVIEW
                                      ──► ACCEPTED (auto-accept per policy)

        HUMAN_REVIEW
            └── human decides ──► ACCEPTED (risk accepted with rationale)
                               ──► DEFERRED (revisit later, logged)
                               ──► AUTO_REMEDIATE (human triggers fix)

    AUTO_REMEDIATE and ACCEPTED are terminal states for the audit trail.
    DEFERRED is terminal for this run but re-surfaces on next scan.
    """
    PENDING = "pending"
    AUTO_REMEDIATE = "auto_remediate"   # policy says fix it automatically
    HUMAN_REVIEW = "human_review"       # routed to HITL gate
    ACCEPTED = "accepted"               # risk accepted, rationale logged
    DEFERRED = "deferred"               # acknowledged, revisit later


class RemediationType(str, Enum):
    """
    Categories of recommended fix for a finding. Different types
    require different downstream handling — auto-remediation logic
    varies by type, and the UI presents them differently.

    Mapping guidance:
        VERSION_BUMP         — Same package, newer version. Highest
                               confidence remediation. Often auto-
                               remediable for non-breaking changes.
        PACKAGE_SWAP         — Replace with a different package that
                               provides equivalent functionality. Always
                               requires human review (API differences,
                               testing impact).
        CONFIG_CHANGE        — Disable the vulnerable feature/code path
                               in your usage. Requires code change but
                               not dependency change.
        COMPENSATING_CONTROL — Mitigate via infrastructure (WAF rule,
                               network egress filter, access restriction).
                               No code or dependency change needed.
        NO_FIX_AVAILABLE     — Vulnerability is acknowledged upstream
                               but no patch exists yet. Action is to
                               monitor and potentially apply a
                               compensating control in the meantime.
        ACCEPT_AS_IS         — Genuine analysis shows the risk is
                               low for this specific use case (e.g.
                               vulnerable code path is unreachable).
                               Always requires explicit human acceptance
                               with rationale.
        MONITOR              — Conditional or audit-required remediation.
                               The CVE's reachability depends on
                               application-specific code or runtime
                               configuration that cannot be determined
                               from the dependency tree alone. The
                               reviewer should audit their codebase for
                               the specific condition described in the
                               contextualization rationale and decide
                               whether to fix, accept, or defer based
                               on what they find. Used by
                               contextualization analysis when the
                               attack vector requires conditions only
                               the application owner can verify.
    """
    VERSION_BUMP = "version_bump"
    PACKAGE_SWAP = "package_swap"
    CONFIG_CHANGE = "config_change"
    COMPENSATING_CONTROL = "compensating_control"
    NO_FIX_AVAILABLE = "no_fix_available"
    ACCEPT_AS_IS = "accept_as_is"
    MONITOR = "monitor"


class CitationSource(str, Enum):
    """
    Source types for evidence backing a finding or remediation.

    Citations are MANDATORY throughout the system — no finding or
    remediation can exist without at least one citation. This is the
    integrity backbone that makes the tool enterprise-credible.

    "I asked Claude" is not a defensible answer in a SOC 2 review.
    Every claim must trace to a source.

    Confidence ranking (rough order, authoritative → inferred):
        OSV, NVD, SPDX            — primary registries
        GHSA, PYPI                — trusted secondary sources
        UPSTREAM_DOCS, CHANGELOG  — package-authored, authoritative
                                    for that package
        UPSTREAM_REPO             — for issues, PRs, code references
        CURATED_MAPPING           — our internal alternatives database;
                                    high quality but limited coverage
        POLICY                    — references org's POLICY.yml; not
                                    external evidence but justifies
                                    auto-decisions
        LLM_INFERENCE             — LLM-generated reasoning, lowest
                                    confidence, always flagged in UI
    """
    OSV = "osv"                          # OSV.dev vulnerability database
    NVD = "nvd"                          # NIST National Vulnerability DB
    GHSA = "ghsa"                        # GitHub Security Advisory
    PYPI = "pypi"                        # PyPI package metadata
    SPDX = "spdx"                        # SPDX license registry
    UPSTREAM_DOCS = "upstream_docs"      # package's own documentation
    UPSTREAM_REPO = "upstream_repo"      # GitHub/GitLab repo
    CHANGELOG = "changelog"              # package CHANGELOG/release notes
    CURATED_MAPPING = "curated_mapping"  # our internal alternatives DB
    LLM_INFERENCE = "llm_inference"      # LLM generated, lowest trust
    POLICY = "policy"                    # references org's POLICY.yml rule
    NONE_FOUND = "none_found"            # explicit "no evidence" marker
    # NONE_FOUND is REQUIRED rather than allowing empty citation lists.
    # Forces absence of evidence to be a positive signal in the UI
    # ("we looked and found nothing") rather than ambiguous missing data
    # ("did we forget to check?").
    #
    # Use NONE_FOUND when:
    #   - LLM proposed a remediation but no authoritative source could
    #     be retrieved to back it up
    #   - A finding is based on heuristic analysis with no citable basis
    #   - We attempted to fetch evidence but the source was unavailable
    #
    # The presence of NONE_FOUND in a Finding/Remediation:
    #   - Forces overall confidence to "low"
    #   - Triggers mandatory HUMAN_REVIEW (cannot auto-remediate)
    #   - Surfaces a prominent warning in the UI
    #   - Is itself an audit artifact: "we documented that we couldn't
    #     find evidence" is more defensible than silence


# ---------------------------------------------------------------------------
# Sub-schemas (nested TypedDicts used inside AgentState)
# ---------------------------------------------------------------------------

class PackageRecord(TypedDict):
    """
    Normalized record for a single resolved package in the dependency tree.

    Produced by: SBOMNode
    Consumed by: LicenseNode, CVENode (both read the full packages list)
    Written back by: LicenseNode and CVENode add findings, not modify
                     PackageRecord directly

    One PackageRecord per unique (name, version) pair. If the same package
    appears as both a direct and transitive dependency, it gets ONE record
    with transitive=False (direct takes precedence).
    """

    name: str
    # Package name exactly as it appears in PyPI e.g. "requests", "Pillow"

    version: str
    # Resolved pinned version e.g. "2.31.0"
    # Always the fully resolved version, never a range like ">=2.0"

    license: Optional[str]
    # SPDX license identifier e.g. "MIT", "Apache-2.0", "GPL-3.0-only"
    # None if PyPI metadata is missing or malformed — triggers "unknown"
    # license_status downstream. SPDX format is critical for machine
    # reasoning; human-readable names like "GNU GPL" are normalized to
    # SPDX by the LicenseNode.

    license_status: Optional[str]
    # Set by LicenseNode after compliance reasoning. Values:
    #   "compliant"   — license permits declared use case
    #   "restricted"  — license has conditions that may apply
    #   "violation"   — license prohibits declared use case
    #   "unknown"     — could not determine license from metadata or
    #                   fallback GitHub LICENSE file check
    # None until LicenseNode has processed this package.

    cves: list[dict]
    # Raw CVE records returned from OSV.dev API for this package+version.
    # Each dict is the full OSV vulnerability object — we store raw and
    # let CVENode reason over it rather than pre-processing here.
    # Empty list [] means clean (no known CVEs), not "not yet checked".
    # None would be ambiguous — always initialize to [].

    license_risk: Optional[RiskLevel]
    # Contextualized license risk for this package. Set by RiskNode.
    # Deliberately kept SEPARATE from security_risk because:
    #   - Different remediation paths (swap package vs. version bump)
    #   - Different decision-makers (legal/compliance vs. security)
    #   - Different temporal urgency (long-term vs. immediate)
    #   - Different audit trail lifetime (permanent vs. time-bounded)
    # Combining them into a single risk_level loses signal — a package
    # with HIGH license risk and LOW security risk averaged to MEDIUM
    # tells the reviewer nothing actionable.
    #
    # RiskNode computes this from:
    #   - license_status (compliant/restricted/violation/unknown)
    #   - use_case (saas/internal/distributed_binary)
    #   - transitive flag (less control over transitive deps may
    #     warrant lower risk if direct alternative is impractical)
    #   - policy.blocked_licenses / policy.allowed_licenses overrides
    #
    # None until RiskNode has processed this package.

    security_risk: Optional[RiskLevel]
    # Contextualized security risk for this package. Set by RiskNode.
    # See license_risk comment above for the design rationale on
    # keeping these dimensions separate.
    #
    # RiskNode computes this from:
    #   - cves list (CVSS scores, fix availability)
    #   - use_case (does the vulnerable code path apply to this
    #     deployment model? a Pillow image-processing CVE in an
    #     internal admin tool with no image upload is LOW actual risk
    #     even if CVSS is CRITICAL)
    #   - transitive flag (transitive CVEs require different
    #     remediation than direct dep CVEs)
    #   - policy thresholds and overrides
    #
    # None until RiskNode has processed this package.

    from_cache: bool
    # True if this record was served from L1 package cache rather than
    # hitting OSV API / pip-licenses live. Surfaced in UI as latency
    # savings metric: "X of Y packages served from cache."

    cached_at: Optional[str]
    # ISO 8601 timestamp of when this record was cached e.g.
    # "2026-05-11T14:32:00Z". Used by cache invalidation logic (v2)
    # to enforce TTL. Stored now even though TTL enforcement is v2 —
    # cheap to stamp, expensive to retrofit later.

    transitive: bool
    # False = direct dependency (explicitly in requirements.txt)
    # True  = transitive dependency (dependency of a dependency)
    # Important for risk prioritization: a CRITICAL CVE in a transitive
    # dep you don't control directly gets a different remediation path
    # than one in a direct dep you can simply version-bump.


class Citation(TypedDict):
    """
    Evidence record backing a finding or remediation.

    REQUIRED: Every Finding must have at least one Citation.
    REQUIRED: Every Remediation must have at least one Citation.
    REQUIRED: Empty citation lists are NEVER allowed — use NONE_FOUND
              to make absence of evidence explicit.
    No exceptions. A finding or remediation without citations is
    rejected during validation.

    This is the integrity backbone of the entire system. Auditors
    must be able to trace every claim back to a source. "The agent
    said so" is not acceptable evidence in enterprise compliance
    contexts (SOC 2, FedRAMP, CMMC).

    Citation source hierarchy (see CitationSource enum):
        - Primary registries (OSV, NVD, SPDX) → highest trust
        - Trusted secondary (GHSA, PYPI) → high trust
        - Package-authored (UPSTREAM_DOCS, CHANGELOG) → high trust
          for that package's own claims
        - Internal (CURATED_MAPPING, POLICY) → medium-high trust
        - LLM_INFERENCE → lowest trust, always flagged in UI
        - NONE_FOUND → explicit "no evidence" marker, flagged in UI

    LLM_INFERENCE citations are allowed but flagged as low confidence
    in the UI and trigger mandatory human review. They count as
    evidence (we're being honest about the source) but they don't
    count as authoritative.

    See module-level CITATION INTEGRITY GUARDRAILS docstring for the
    full architectural defense against hallucinated citations.
    """

    source: CitationSource
    # Which type of source this citation comes from. Drives confidence
    # display in UI and audit trail filtering.

    url: Optional[str]
    # Canonical URL when available. Examples:
    #   OSV: "https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx"
    #   NVD: "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX"
    #   SPDX: "https://spdx.org/licenses/MIT.html"
    # None for sources without a public URL (e.g. CURATED_MAPPING,
    # LLM_INFERENCE, POLICY).

    identifier: Optional[str]
    # Source-specific identifier. Examples:
    #   "CVE-2024-1234" for NVD/OSV
    #   "GHSA-xxxx-xxxx-xxxx" for GHSA
    #   "MIT" for SPDX
    #   "policy.blocked_licenses[3]" for POLICY references
    # None when no stable identifier exists.

    excerpt: Optional[str]
    # Short relevant quoted text from the source (under 100 chars).
    # Helpful for human reviewers who want context without clicking
    # through to the source. Example: "Allows remote code execution
    # via crafted input." Keep brief — not a summary, just a pointer.

    retrieved_at: str
    # ISO 8601 timestamp of when this citation was fetched.
    # Critical for audit trail — proves what the source said AT THE TIME
    # of the scan, even if the source later changes.
    # Example: "2026-05-15T14:32:00Z"

    confidence: str
    # Citation strength. Values:
    #   "authoritative" — primary source (OSV record, SPDX registry,
    #                     upstream changelog from package maintainer)
    #   "reliable"      — secondary trusted source (GHSA mirroring CVE,
    #                     curated mapping with manual verification)
    #   "inferred"      — LLM-generated reasoning. Always triggers
    #                     UI warning and mandatory human review.
    #   "none"          — for NONE_FOUND citations only
    # A finding/remediation with ONLY "inferred" or "none" citations
    # is downgraded to low confidence and cannot be auto-remediated.

    validated: bool
    # Has this citation passed validation checks?
    # Set to True only after:
    #   - URL liveness check passes (HTTP HEAD returns 2xx) for URL
    #     citations
    #   - Identifier format check passes (regex match for CVE-XXXX-XXXXX,
    #     GHSA-xxxx-xxxx-xxxx, etc.) for identifier-only citations
    #   - The citation IS the API response we directly received (highest
    #     confidence — no validation needed because we got it from source)
    # Citations with validated=False are surfaced in UI with warnings
    # and cannot back high-confidence remediations.
    # Always False for NONE_FOUND citations (nothing to validate).

    validation_method: str
    # How this citation was validated. Values:
    #   "api_response"   — Citation IS the API response we received
    #                      directly from the source. Highest confidence
    #                      because there's no separate URL to verify.
    #   "url_live"       — HTTP HEAD returned 2xx within last scan
    #   "url_failed"     — HTTP HEAD failed or returned 4xx/5xx
    #                      (citation kept for audit trail but flagged)
    #   "format_check"   — Identifier matches expected format pattern
    #                      (weaker — format match doesn't prove existence)
    #   "not_validated"  — Validation skipped (e.g. POLICY references
    #                      that point to in-memory config, not URLs)
    #   "none_found"     — No evidence to validate (NONE_FOUND citations)

    content_hash: str
    # SHA-256 hex digest of the canonical serialization of all other
    # Citation fields at the moment of creation. Computed ONCE,
    # NEVER updated.
    #
    # Canonical serialization: JSON dump of all fields except
    # content_hash itself, with sorted keys and stable formatting.
    # This ensures hash determinism regardless of field insertion order.
    #
    # Purpose: per-citation tamper detection that complements the
    # audit_trail's hash chain. The audit_trail entry that records
    # this Citation's creation includes this content_hash in its
    # payload. Cross-referencing the two enables independent integrity
    # checks:
    #   - If state's Citation has a different content_hash than what
    #     the audit_trail recorded → state was tampered with
    #   - If audit_trail's hash chain is broken → audit log was tampered
    # An attacker would need to compromise BOTH the state AND the
    # audit trail consistently to hide tampering — much harder than
    # either one alone.
    #
    # Verification function (separate utility, not in this schema):
    #   compute_content_hash(citation) == citation["content_hash"]
    # Any mismatch = tampering detected.


class Remediation(TypedDict):
    """
    A specific recommended fix for a Finding.

    Multiple Remediations per Finding is the norm, not the exception.
    A CVE often has multiple valid fix paths (version bump, compensating
    control, accept-as-is given context). The UI presents the highest-
    confidence option as primary, others as alternatives.

    Produced by: LicenseNode/CVENode (basic options) and enriched by
                 RiskNode (use-case-aware options like compensating
                 controls)
    """

    type: RemediationType
    # Category of fix. Drives UI presentation and (eventual) auto-
    # remediation logic.

    description: str
    # Human-readable explanation of the fix. Example:
    # "Upgrade requests to version 2.32.0 which patches CVE-2024-XXXXX
    #  with no breaking API changes."

    target_package: Optional[str]
    # For PACKAGE_SWAP: the alternative package name e.g. "httpx"
    # None for other remediation types.

    target_version: Optional[str]
    # For VERSION_BUMP: the safe version to upgrade to e.g. "2.32.0"
    # For PACKAGE_SWAP: the version of the target_package to use
    # None for remediation types where version isn't applicable.

    confidence: str
    # Overall confidence in this remediation. Values:
    #   "high"    — authoritative citations, well-tested fix path
    #   "medium"  — reliable citations, some uncertainty (e.g. swap
    #               with API differences)
    #   "low"     — inferred-only citations, requires human judgment
    # Drives UI prominence (high-confidence shown first) and gates
    # auto-remediation (only "high" can auto-remediate).

    rationale: str
    # Why THIS specific remediation is recommended over alternatives.
    # Example: "Version 2.32.0 is the minimum patched release; later
    #  versions add unrelated features. This minimizes diff for review."

    tradeoffs: Optional[str]
    # What changes if this remediation is applied. Critical for
    # PACKAGE_SWAP and CONFIG_CHANGE types. Example:
    # "httpx has slightly different API for streaming responses —
    #  iter_bytes() instead of iter_content(). ~5 call sites in your
    #  codebase would need updating."
    # None when there are no significant tradeoffs (e.g. patch-level
    # version bumps).

    citations: list[Citation]
    # REQUIRED, non-empty. Evidence backing this remediation.
    # A remediation without citations is rejected during validation.
    # Example for VERSION_BUMP:
    #   - Citation pointing to OSV record showing 2.32.0 fixes CVE
    #   - Citation pointing to requests changelog for 2.32.0
    # Example for PACKAGE_SWAP:
    #   - Citation pointing to SPDX entry for both packages' licenses
    #   - Citation pointing to CURATED_MAPPING entry confirming
    #     functional equivalence


class Finding(TypedDict):
    """
    A single actionable compliance or security finding for one package.

    Produced by: LicenseNode (license findings) and CVENode (CVE findings)
    Merged by: RiskNode into risk_matrix
    Resolved by: DecisionGateNode (HITL) or AutoRemediateNode

    One Finding per issue per package. A package with both a license
    violation AND a CVE produces two separate Finding objects so each
    can be tracked and decided independently.
    """

    finding_id: str
    # UUID v4 generated at Finding creation. Stable identifier used to
    # match decisions back to findings across the audit trail.
    # Format: "f-{uuid4}" e.g. "f-3a7b9c2d-..."

    package: str
    # Package name this finding applies to. Matches PackageRecord.name.

    version: str
    # Package version this finding applies to. Matches PackageRecord.version.

    finding_type: str
    # Categorical type of finding. Values:
    #   "license_violation"   — license prohibits declared use case
    #   "license_restricted"  — license has conditions requiring attention
    #   "license_unknown"     — could not determine license
    #   "cve"                 — known CVE with OSV record
    #   "cve_no_fix"          — CVE exists but no patched version available

    severity: RiskLevel
    # Severity of this specific finding. Set by LicenseNode or CVENode.
    # For CVEs: derived from CVSS score via RiskLevel mapping above.
    # For license: derived from license type + use case combination.

    description: str
    # Human-readable explanation of the finding. LLM-generated with
    # specific context e.g.:
    # "GPL-3.0-only license detected. Your declared use case (SaaS) 
    #  requires distributing the software, which triggers copyleft 
    #  obligations under GPL-3.0."
    # This is what appears in the UI finding card.

    recommendation: str
    # High-level human-readable summary of the recommended action.
    # Generated alongside the structured remediations list — this is
    # the one-liner that appears in summary views and notifications.
    # The full structured options live in `remediations` below.
    # Example: "Upgrade requests to 2.32.0 (patch available)."

    remediations: list[Remediation]
    # Ranked list of structured remediation options, best-first.
    # Often multiple — a CVE might have a version bump available AND
    # a compensating control AND an accept-as-is option for low-risk
    # use cases. The UI surfaces the top option prominently and
    # presents alternatives as "other options."
    #
    # Two-stage generation:
    #   Stage 1 (LicenseNode/CVENode): basic options (version bumps
    #     from OSV "fixed" field, package swaps from CURATED_MAPPING)
    #   Stage 2 (RiskNode): use-case-aware options (compensating
    #     controls only make sense once we know the deployment model)
    #
    # Empty list is allowed but rare — would mean "no action available,
    # finding is informational only."

    citations: list[Citation]
    # REQUIRED, non-empty. Evidence backing the FINDING itself
    # (separate from remediation citations).
    # A finding without citations is rejected during validation.
    # Example for a CVE finding:
    #   - Citation [OSV record URL with confidence="authoritative"]
    #   - Citation [NVD entry URL with confidence="authoritative"]
    # Example for a license violation finding:
    #   - Citation [SPDX entry for the license]
    #   - Citation [POLICY rule that classified this license as
    #     incompatible with the use_case]
    #
    # This is independent of remediation citations because the FACT
    # of a violation needs evidence separately from the proposed FIX.
    # Auditors trace both: "show me the CVE record" AND "show me why
    # the recommended fix is the right one."

    decision_status: DecisionStatus
    # Current lifecycle status. Initialized to PENDING by producing node.
    # Updated by RiskNode (routing) and DecisionGateNode (resolution).

    decision_rationale: Optional[str]
    # Human-provided rationale when decision_status is ACCEPTED or DEFERRED.
    # Required for audit trail completeness — an accepted risk with no
    # rationale is an audit failure in enterprise compliance contexts.
    # None for AUTO_REMEDIATE (no human involved).

    decided_at: Optional[str]
    # ISO 8601 timestamp of decision e.g. "2026-05-15T09:41:00Z"
    # None until a terminal decision is made.

    decided_by: Optional[str]
    # Who/what made the decision. Values:
    #   "auto"    — policy-driven automatic decision
    #   "human"   — human via HITL gate
    # None until decided.

    prior_decision: Optional[dict]
    # L2 Decision Memory hit. If this (package, version, finding_type,
    # use_case, policy_hash) combination was previously decided by a human,
    # this field carries that prior decision record so the HITL gate can
    # surface: "You reviewed this on [date] and accepted with rationale: X.
    # Policy unchanged. Confirm or re-review?"
    # None if no prior decision found in L2 memory.
    # This is a key UX differentiator — enterprise compliance teams
    # hate re-litigating decisions they already made.

    contextualized_severity: Optional[RiskLevel]
    # Set by RiskNode for HIGH/CRITICAL CVE findings only. The LLM
    # evaluates whether the raw CVSS severity is materially different
    # given the user's declared use_case (e.g. a Pillow image-processing
    # CVE in an internal admin tool with no image upload is LOW actual
    # risk even if raw CVSS is CRITICAL).
    # None for findings that weren't contextualized (LOW/MEDIUM CVEs,
    # license findings, or when contextualization fails defensively).
    # Routing uses max(severity, contextualized_severity) — the LLM
    # can never downgrade a CRITICAL past the human-review gate.

    contextualization_rationale: Optional[str]
    # One-to-two sentence rationale generated alongside
    # contextualized_severity. Format: "{LLM analysis}. Confidence:
    # {high|medium|low}. Reviewer should verify."
    # None when contextualization didn't run.


# ---------------------------------------------------------------------------
# Primary State Schema
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    """
    The complete shared state for one compliance scan job.

    This TypedDict is passed between every node in the LangGraph graph.
    LangGraph merges node return values back into this state automatically
    using reducers (see Annotated fields below for append-only behavior).

    Lifecycle of a scan:
        1. InputNode        populates job_id, input_*, use_case, policy
        2. SBOMNode         populates raw_dependency_tree, packages
        3. LicenseNode  ─┐  both run concurrently (async)
           CVENode      ─┘  populate license_findings, cve_findings
        4. RiskNode         merges findings → risk_matrix, routes to
                            pending_human_review or resolved_findings
        5. DecisionGateNode human resolves pending_human_review
        6. AuditNode        writes all decisions to audit_trail
        7. ReportNode       generates final report from resolved state

    Field groupings below match this lifecycle order.
    """

    # -----------------------------------------------------------------------
    # Input Layer
    # Fields set once by InputNode, read-only for all downstream nodes.
    # -----------------------------------------------------------------------

    job_id: str
    # UUID v4 identifying this scan run. Used as:
    #   - Primary key in L1/L2 cache lookups
    #   - Filename stem for audit_trail.jsonl
    #   - API path parameter e.g. GET /scan/results/{job_id}
    # Format: "job-{uuid4}"

    input_type: str
    # How the user provided their dependency information. Values:
    #   "repo_url"          — GitHub/GitLab repo URL, agent clones and
    #                         finds requirements.txt / pyproject.toml
    #   "requirements_file" — direct file upload or path

    input_value: str
    # The actual input: URL string or file path depending on input_type.

    use_case: str
    # User-declared deployment/distribution model. Critical for license
    # compatibility reasoning — the same license can be compliant or
    # violating depending on use case. Values:
    #   "saas"              — software delivered as a service over network
    #   "internal"          — internal tooling, never distributed
    #   "distributed_binary"— shipped to end users as an installable package
    # This field is injected into every LLM prompt that reasons about
    # license compatibility.

    policy: dict
    # Parsed contents of POLICY.yml — the organization's risk tolerance
    # configuration. Loaded once at input, carried through state.
    # Structure mirrors POLICY.yml schema (defined separately).
    # Key fields the RiskNode reads:
    #   policy["auto_remediate_below"]  — RiskLevel threshold for auto-fix
    #   policy["auto_accept_below"]     — RiskLevel threshold for auto-accept
    #   policy["blocked_licenses"]      — list of SPDX IDs always flagged
    #   policy["allowed_licenses"]      — list of SPDX IDs always approved

    # -----------------------------------------------------------------------
    # SBOM Layer
    # Set by SBOMNode after resolving the full dependency tree.
    # -----------------------------------------------------------------------

    raw_dependency_tree: dict
    # Raw JSON output from pipdeptree --json-tree. Preserved as-is for
    # auditability — if a user questions why a transitive dep was flagged,
    # we can show them the exact tree that produced it.
    # Not used directly by downstream nodes — they use `packages` instead.

    packages: list[PackageRecord]
    # Normalized, flat list of all resolved packages (direct + transitive).
    # SBOMNode de-duplicates (name, version) pairs and checks L1 cache
    # for each before hitting PyPI/OSV APIs.
    # This is the primary input to LicenseNode and CVENode.

    # -----------------------------------------------------------------------
    # License + CVE Layer
    # Set concurrently by LicenseNode and CVENode (async parallel execution).
    # These nodes do NOT modify `packages` directly — they produce findings.
    # -----------------------------------------------------------------------

    license_findings: list[Finding]
    # All license compliance findings produced by LicenseNode.
    # One Finding per package with a non-NONE license issue.
    # Clean packages (compliant, no conditions) produce no Finding.

    cve_findings: list[Finding]
    # All CVE/vulnerability findings produced by CVENode.
    # One Finding per CVE per package (a package with 3 CVEs = 3 Findings).
    # This granularity allows independent decisions per CVE.

    raw_osv_records: dict
    # Map of finding_id -> raw OSV vulnerability record. Populated by
    # CVENode alongside cve_findings; consumed by RiskNode to ground
    # the use-case contextualization LLM prompts. Kept in state rather
    # than on each Finding to keep the Finding shape lean and avoid
    # serializing the full OSV blob in API responses. Internal-only;
    # never surfaced through the user-facing API.

    # -----------------------------------------------------------------------
    # Risk Layer
    # Set by RiskNode after merging license_findings + cve_findings.
    # -----------------------------------------------------------------------

    risk_matrix: list[Finding]
    # Merged and ranked list of ALL findings (license + CVE), sorted by
    # severity descending. This is what the UI risk matrix visualizes.
    #
    # IMPORTANT: License findings and CVE findings are kept as separate
    # entities in this list — never merged into a unified risk score.
    # The UI presents them as two parallel dimensions per package:
    #
    #   Package          License Risk    Security Risk    Action
    #   ────────────────────────────────────────────────────────────
    #   requests 2.28    NONE            HIGH             Review CVE
    #   somelib 1.0      CRITICAL        NONE             Replace pkg
    #   oldlib 0.9       MEDIUM          MEDIUM           Two-track
    #
    # RiskNode sets decision_status on each finding based on policy:
    #   - severity below auto_remediate threshold → AUTO_REMEDIATE
    #   - severity below auto_accept threshold    → ACCEPTED
    #   - everything else                         → HUMAN_REVIEW
    # These thresholds can be configured separately for license vs.
    # security findings in POLICY.yml.

    risk_summary: Optional[str]
    # LLM-generated executive summary of the overall risk posture.
    # Written in plain language for a non-technical audience. Example:
    # "15 packages scanned. 2 critical findings require immediate attention:
    #  a GPL license violation in 'somelib' and a CVE-2024-XXXX in
    #  'anotherlib' with a patch available. 8 findings were auto-resolved
    #  per policy. 5 packages are fully compliant."
    # This is the first thing shown in Ashu's dashboard header.

    # -----------------------------------------------------------------------
    # Decision Layer
    # Managed by RiskNode (routing) and DecisionGateNode (resolution).
    # -----------------------------------------------------------------------

    pending_human_review: list[Finding]
    # Findings routed to HITL gate — awaiting human decision.
    # When this list is non-empty, status = "awaiting_human" and the
    # pipeline pauses at DecisionGateNode until all are resolved.
    # The UI surfaces these as action items requiring attention.

    resolved_findings: Annotated[list[Finding], operator.add]
    # All findings with a terminal decision_status (ACCEPTED, AUTO_REMEDIATE,
    # DEFERRED). Populated by RiskNode (auto-decisions) AND incrementally
    # by DecisionGateNode each time a human resolves a finding. The
    # operator.add reducer is REQUIRED here — without it DecisionGateNode's
    # append on resume would clobber RiskNode's auto-decided findings
    # (last-write-wins under default merge semantics).
    #
    # pending_human_review intentionally has NO reducer — DecisionGateNode
    # needs to *replace* it with the shrinking remainder, not append.

    # -----------------------------------------------------------------------
    # Audit Layer
    # Append-only. Uses Annotated[list, operator.add] reducer so multiple
    # nodes can safely append entries concurrently without race conditions.
    # Never overwrite. Never delete. This is the compliance record.
    # -----------------------------------------------------------------------

    audit_events: Annotated[list[dict], operator.add]
    # Staging buffer for raw, NOT-YET-hash-chained events emitted by every
    # node during the scan. Each entry has the shape:
    #   {
    #     "timestamp": str,    # ISO 8601, set by the producing node
    #     "event_type": str,   # "scan_started" | "sbom_resolved" |
    #                          #   "license_scanned" | "cve_scanned" |
    #                          #   "decision_made" | etc.
    #     "payload": dict,     # event-specific data
    #   }
    # AuditNode runs last, sorts these by timestamp, and writes the
    # hash-chained `audit_trail` below in a single deterministic pass.
    # The operator.add reducer is REQUIRED here — LicenseNode and CVENode
    # run in parallel and would otherwise clobber each other's writes.

    audit_trail: Annotated[list[dict], operator.add]
    # Hash-chained append-only log of every significant event in the scan.
    # Written by AuditNode by sealing `audit_events` (above) into a chain.
    # Each entry has the structure:
    #   {
    #     "seq": int,              # monotonic sequence number
    #     "timestamp": str,        # ISO 8601
    #     "event_type": str,       # "scan_started" | "finding_created" |
    #                              #   "decision_made" | "cache_hit" | etc.
    #     "payload": dict,         # event-specific data
    #     "prev_hash": str,        # SHA-256 of previous entry (chain)
    #     "entry_hash": str        # SHA-256 of this entry
    #   }
    # Hash chaining means any tampering with a past entry invalidates all
    # subsequent hashes — providing tamper-evident audit trail for
    # enterprise compliance (SOC 2, FedRAMP, CMMC auditors love this).
    # operator.add reducer = list concatenation, safe for concurrent appends.

    # -----------------------------------------------------------------------
    # Meta Layer
    # Pipeline health tracking. Also append-only for errors.
    # -----------------------------------------------------------------------

    errors: Annotated[list[str], operator.add]
    # Non-fatal errors accumulated during the scan. The pipeline continues
    # on non-fatal errors (e.g. "could not fetch license for package X,
    # falling back to unknown") but logs them here for transparency.
    # Fatal errors set status = "failed" and halt the graph.
    # operator.add reducer = safe concurrent appends from parallel nodes.

    status: str
    # Current pipeline status. Values:
    #   "running"          — pipeline is executing
    #   "awaiting_human"   — paused at HITL gate, pending_human_review
    #                        is non-empty
    #   "complete"         — all findings resolved, report generated
    #   "failed"           — fatal error, check errors list
    # This is the field Ashu's dashboard polls to drive UI state
    # (loading spinner → action required banner → results view).
