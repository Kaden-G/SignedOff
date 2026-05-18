# =============================================================================
# API Contract — SignedOff Compliance Agent
# =============================================================================
#
# This document is the authoritative request/response contract between
# Kaden's FastAPI backend and Ashu's Lovable frontend.
#
# STATUS: LOCKED for v1. Do not change shapes without notifying Ashu.
#
# Design rules:
#   1. use_case is echoed on EVERY response that contains findings,
#      decisions, or audit data. This is deliberate — it makes the
#      declared use case visible in the UI at every step so users
#      cannot later claim "I didn't know it was evaluated as SaaS."
#      It also protects the audit trail: the use_case at evaluation
#      time is recorded, not just at scan initiation.
#
#   2. Severity values are always lowercase strings matching RiskLevel:
#      "critical" | "high" | "medium" | "low" | "none"
#
#   3. decision_status values match DecisionStatus:
#      "pending" | "auto_remediate" | "human_review" | "accepted" | "deferred"
#
#   4. Timestamps are always ISO 8601 UTC strings:
#      "2026-05-13T14:32:00Z"
#
#   5. All list endpoints return empty arrays [], never null, when there
#      is no data. Frontend should never need to null-check a list field.
#
#   6. finding_id format: "f-{uuid4}"  e.g. "f-3a7b9c2d-1e4f-..."
#      job_id format:     "job-{uuid4}" e.g. "job-8f2c1a9b-..."
#
# CORS: Backend must include Access-Control-Allow-Origin: * header.
#       Ashu's Lovable frontend origin varies; wildcard is fine for hackathon.
#
# BASE URL (production placeholder): https://signedoff-api.fly.dev
# BASE URL (local dev):              http://localhost:8000
# =============================================================================


# =============================================================================
# POST /scan/start
# =============================================================================
# Kick off a new compliance scan. Returns a job_id immediately.
# The scan runs asynchronously — poll /scan/status/{job_id} for progress.
#
# Ashu mock: hardcode job_id = "job-demo-001" for static mockups.
# -----------------------------------------------------------------------------

REQUEST:
  Method: POST
  Path:   /scan/start
  Headers:
    Content-Type: application/json

  Body:
    {
      "input_type": "requirements_file",
        # Required. Currently the only accepted value: "requirements_file".
        # "repo_url" was a v1 input type but never implemented real cloning
        # — it silently returned the server's running venv as the scan
        # result. Removed at the API layer following the 2026-05-17 smoke
        # test. Real repo URL ingestion is v1.1 roadmap.

      "input_value": "base64-encoded file contents",
        # Required. base64-encoded UTF-8 contents of a requirements.txt file.

      "use_case": "saas",
        # Required. "saas" | "internal" | "distributed_binary"
        # This is the MOST IMPORTANT field — drives all license reasoning.
        # Echoed back on every subsequent response for this job.

      "policy_override": null
        # Optional. If null, uses the server's default POLICY.yml.
        # If provided, a partial POLICY.yml object that overrides specific
        # fields. v1: always send null. v2 feature.
    }

RESPONSE 202 Accepted:
    {
      "job_id": "job-8f2c1a9b-4d3e-4f1a-9b2c-1a3b4c5d6e7f",
        # Stable identifier for this scan run. Use in all subsequent requests.

      "use_case": "saas",
        # Echoed back immediately — confirms what was recorded.
        # Frontend should display this prominently: "Scanning as: SaaS"

      "status": "running",
        # Always "running" on 202. Poll /scan/status for updates.

      "created_at": "2026-05-13T14:32:00Z"
    }

RESPONSE 422 Unprocessable Entity (validation error):
    {
      "error": "invalid_use_case",
      "message": "use_case must be one of: saas, internal, distributed_binary",
      "field": "use_case"
    }

RESPONSE 400 Bad Request (e.g. unparseable requirements file):
    {
      "error": "parse_error",
      "message": "Could not parse requirements file: line 14 is malformed",
      "field": "input_value"
    }


# =============================================================================
# GET /scan/status/{job_id}
# =============================================================================
# Rich polling endpoint. Frontend polls this every 2 seconds while status
# is "running" or "awaiting_human".
#
# Designed for Ashu's live feed UI:
#   - Phase banner ("Checking CVEs...")
#   - Per-package progress list (scrolling, newest at top)
#   - Cache hit counter ("34 of 108 packages from cache")
#   - Overall progress bar (packages_analyzed / packages_total)
#
# Ashu mock: simulate packages being added to current_activity[] over time.
# -----------------------------------------------------------------------------

REQUEST:
  Method: GET
  Path:   /scan/status/{job_id}

RESPONSE 200 OK:
    {
      "job_id": "job-8f2c1a9b-...",

      "use_case": "saas",
        # Always echoed. Frontend keeps this visible throughout the scan.

      "status": "running",
        # "running"        — scan is executing, keep polling
        # "awaiting_human" — paused at HITL gate, check /scan/pending-review
        # "complete"       — done, fetch /scan/results and /scan/risk-matrix
        # "failed"         — fatal error, see errors[]

      "current_phase": "cve_scan",
        # Human-readable phase name for the phase banner.
        # Values (in order):
        #   "resolving_dependencies"  — SBOMNode running
        #   "license_scan"            — LicenseNode running
        #   "cve_scan"                — CVENode running
        #   "risk_analysis"           — RiskNode running
        #   "awaiting_review"         — DecisionGateNode paused
        #   "finalizing"              — AuditNode + ReportNode running
        #   "complete"
        #   "failed"

      "progress_pct": 42,
        # Integer 0-100. Computed as:
        #   (packages_analyzed / packages_total) * 100
        # Drives the progress bar fill.

      "packages_total": 108,
        # Total packages in the resolved dependency tree.
        # Available after SBOMNode completes (~3-5 sec into scan).
        # 0 until SBOMNode finishes.

      "packages_analyzed": 45,
        # Packages that have completed both license + CVE checks.
        # Increments as parallel checks complete.

      "cache_hits": 34,
        # Packages served from L1 cache (no live API call needed).
        # Display as: "34 of 108 packages from cache"
        # This is a key demo metric — surfaces the latency savings story.

      "current_activity": [
        # Ordered list of recent per-package events, newest first.
        # Frontend displays this as a scrolling live feed.
        # Backend keeps last 20 entries; frontend shows last 8-10.
        {
          "package": "django",
          "version": "4.2.3",
          "event": "cve_found",
            # "checking"       — check in progress
            # "cve_found"      — at least one CVE found (show warning icon)
            # "cve_clean"      — no CVEs found
            # "license_found"  — license identified
            # "license_issue"  — license violation or restriction found
            # "from_cache"     — served from L1 cache
          "detail": "2 CVEs found (CRITICAL)",
            # Short human-readable detail string. Null if none.
          "timestamp": "2026-05-13T14:32:04Z"
        },
        {
          "package": "requests",
          "version": "2.28.0",
          "event": "cve_found",
          "detail": "1 CVE found (MEDIUM)",
          "timestamp": "2026-05-13T14:32:03Z"
        },
        {
          "package": "certifi",
          "version": "2024.2.2",
          "event": "from_cache",
          "detail": null,
          "timestamp": "2026-05-13T14:32:03Z"
        }
      ],

      "findings_preview": {
        # Running count of findings as they're discovered.
        # Lets the frontend show "3 critical findings so far" during scan.
        # Resets to final counts when status = "complete".
        "critical": 2,
        "high": 1,
        "medium": 2,
        "low": 0,
        "total": 5
      },

      "errors": [],
        # Non-fatal error strings. Empty array if none.
        # Example: ["Could not fetch license for package foo==1.0, using unknown"]

      "started_at": "2026-05-13T14:32:00Z",
      "completed_at": null
        # ISO 8601 timestamp when scan completed. Null until status = "complete".
    }

RESPONSE 404 Not Found:
    {
      "error": "job_not_found",
      "message": "No scan job found with id job-8f2c1a9b-..."
    }


# =============================================================================
# GET /scan/results/{job_id}
# =============================================================================
# Idempotent across the scan lifecycle. Serves partial analysis data when
# the scan is mid-flight or paused at the HITL gate, final data once the
# scan completes. Same URL works in all three states — the UI doesn't
# need to know which state it's in to call the endpoint.
#
# The response carries a `scan_status` field mirroring /scan/status so
# the UI can label the view as partial if needed:
#   - "running"        → packages and findings analyzed so far
#   - "awaiting_human" → all analysis done; some findings need decisions
#   - "complete"       → final stored report (audit trail sealed, summary set)
#   - "failed"         → see errors[]
#
# For partial views (scan_status != "complete"):
#   - packages[], license_findings[], cve_findings[] reflect work so far
#   - executive_summary / completed_at may be null (set on completion)
#   - dependency_chain populates normally for any package already analyzed
#
# Ashu mock: use the seeded findings from demo_requirements.txt.
# -----------------------------------------------------------------------------

REQUEST:
  Method: GET
  Path:   /scan/results/{job_id}

RESPONSE 200 OK:
    {
      "job_id": "job-8f2c1a9b-...",

      "scan_status": "complete",
        # Same vocabulary as /scan/status. Tells the UI whether this is
        # a final report or a partial mid-scan snapshot.
        # Values: "running" | "awaiting_human" | "complete" | "failed"

      "use_case": "saas",
        # Echoed. This is the context under which ALL findings were evaluated.
        # Frontend should show this prominently: "Evaluated as: SaaS application"
        # This is the "cover your butt" field — audit trail shows the user
        # declared this use case at scan initiation.

      "scanned_at": "2026-05-13T14:32:00Z",
      "completed_at": "2026-05-13T14:32:31Z",

      "summary": {
        "packages_total": 108,
        "packages_direct": 45,
        "packages_transitive": 63,
        "cache_hits": 34,
        "scan_duration_seconds": 31,

        "findings_total": 7,
        "findings_by_severity": {
          "critical": 2,
          "high": 2,
          "medium": 3,
          "low": 0
        },
        "findings_by_type": {
          "license_violation": 1,
          "license_restricted": 2,
          "cve": 4
        },
        "decisions": {
          "pending_human_review": 3,
          "auto_remediated": 2,
          "auto_accepted": 2
        }
      },

      "executive_summary": "108 packages scanned across 45 direct and 63 transitive dependencies. 7 findings require attention: 2 critical (a GPL license violation in mysqlclient and a SQL injection CVE in Django 4.2.3), 2 high, and 3 medium severity. 4 findings were automatically resolved per policy. 3 critical and high findings are awaiting your review.",
        # LLM-generated plain language summary. Null if generation failed.

      "packages": [
        # Full PackageRecord list. One entry per resolved package.
        # Sorted: findings first (by severity desc), clean packages last.
        {
          "name": "django",
          "version": "4.2.3",
          "license": "BSD-3-Clause",
          "license_status": "compliant",
          "license_risk": "none",
          "security_risk": "critical",
          "transitive": false,
          "from_cache": false,
          "cached_at": null,
          "cves": [
            # Raw OSV response objects — stored as-is for auditability
            { "id": "GHSA-qm57-vhq3-3fwf", "summary": "...", "... ": "..." }
          ]
        }
        # ... remaining packages
      ],

      "license_findings": [
        # All license findings. Empty array if none.
        {
          "finding_id": "f-3a7b9c2d-...",
          "package": "mysqlclient",
          "version": "2.1.1",
          "finding_type": "license_violation",
          "severity": "critical",
          "use_case": "saas",
            # Echoed at the finding level too — makes per-finding context explicit.
          "description": "GPL-2.0-only license detected. Your declared use case (SaaS) distributes the software over a network, which triggers copyleft obligations under GPL-2.0.",
          "recommendation": "Replace mysqlclient with PyMySQL==1.1.0 (MIT license, functionally equivalent).",
          "decision_status": "human_review",
          "decision_rationale": null,
          "decided_at": null,
          "decided_by": null,
          "prior_decision": null,
          "remediations": [
            {
              "type": "package_swap",
              "description": "Replace mysqlclient with PyMySQL==1.1.0",
              "target_package": "PyMySQL",
              "target_version": "1.1.0",
              "confidence": "high",
              "rationale": "PyMySQL is a pure-Python MySQL driver with MIT license and near-identical API surface.",
              "tradeoffs": "PyMySQL is slightly slower than mysqlclient for high-throughput workloads (pure Python vs C extension). Acceptable for most enterprise apps.",
              "citations": [
                {
                  "source": "spdx",
                  "url": "https://spdx.org/licenses/GPL-2.0-only.html",
                  "identifier": "GPL-2.0-only",
                  "excerpt": "You may not impose any further restrictions on the exercise of the rights granted or affirmed under this License.",
                  "retrieved_at": "2026-05-13T14:32:05Z",
                  "confidence": "authoritative",
                  "validated": true,
                  "validation_method": "api_response",
                  "content_hash": "a1b2c3d4..."
                }
              ]
            }
          ],
          "citations": [
            {
              "source": "spdx",
              "url": "https://spdx.org/licenses/GPL-2.0-only.html",
              "identifier": "GPL-2.0-only",
              "excerpt": "The GNU General Public License is a free, copyleft license.",
              "retrieved_at": "2026-05-13T14:32:05Z",
              "confidence": "authoritative",
              "validated": true,
              "validation_method": "api_response",
              "content_hash": "e5f6a7b8..."
            },
            {
              "source": "policy",
              "url": null,
              "identifier": "policy.licenses.blocked[0]",
              "excerpt": "GPL-2.0-only is in the organization blocked license list.",
              "retrieved_at": "2026-05-13T14:32:05Z",
              "confidence": "authoritative",
              "validated": true,
              "validation_method": "not_validated",
              "content_hash": "c9d0e1f2..."
            }
          ]
        }
        # ... remaining license findings
      ],

      "cve_findings": [
        # All CVE findings. Empty array if none.
        # One finding per CVE per package.
        {
          "finding_id": "f-7d8e9f0a-...",
          "package": "django",
          "version": "4.2.3",
          "finding_type": "cve",
          "severity": "critical",
          "use_case": "saas",
            # Echoed at finding level.
          "description": "CVE-2024-42005: SQL injection vulnerability via QuerySet.annotate(), alias(), aggregate(), and extra() on MySQL and MariaDB. Affects Django < 4.2.14.",
          "recommendation": "Upgrade Django to 4.2.14 (minimum patched version).",
          "decision_status": "human_review",
          "decision_rationale": null,
          "decided_at": null,
          "decided_by": null,
          "prior_decision": null,
          "remediations": [
            # NOTE: for HIGH/CRITICAL CVE findings, the remediations list may
            # contain TWO entries:
            #   1. version_bump — authoritative, OSV-cited, identifies the
            #      patched version (or commit ref if no released fix yet).
            #   2. A context-aware remediation — LLM_INFERENCE-cited,
            #      generated by RiskNode contextualization analysis. Its
            #      type is one of: version_bump, accept_as_is,
            #      compensating_control, monitor. The UI should display
            #      this as an alternative to the authoritative
            #      recommendation and flag the LLM_INFERENCE citation.
            #
            # Possible RemediationType values:
            #   version_bump          — same package, newer version (highest confidence)
            #   package_swap          — replace with a different package
            #   config_change         — disable the vulnerable feature/code path
            #   compensating_control  — mitigate via infrastructure (WAF, egress filter, etc.)
            #   no_fix_available      — acknowledged upstream but no patch yet
            #   accept_as_is          — risk accepted with documented rationale
            #   monitor               — conditional/audit-required: reachability depends
            #                           on application-specific code that the reviewer must
            #                           inspect (e.g. "audit your codebase for custom
            #                           Storage subclasses"). Used by contextualization
            #                           analysis when the attack vector requires conditions
            #                           only the application owner can verify.
            {
              "type": "version_bump",
              "description": "Upgrade django from 4.2.3 to 4.2.14",
              "target_package": null,
              "target_version": "4.2.14",
              "confidence": "high",
              "rationale": "4.2.14 is the minimum version patching CVE-2024-42005. Stays on 4.2.x LTS branch — no breaking changes.",
              "tradeoffs": null,
              "citations": [
                {
                  "source": "osv",
                  "url": "https://osv.dev/vulnerability/GHSA-qm57-vhq3-3fwf",
                  "identifier": "GHSA-qm57-vhq3-3fwf",
                  "excerpt": "Fixed in Django 4.2.14, 5.0.7.",
                  "retrieved_at": "2026-05-13T14:32:08Z",
                  "confidence": "authoritative",
                  "validated": true,
                  "validation_method": "api_response",
                  "content_hash": "b3c4d5e6..."
                }
              ]
            },
            {
              # Context-aware remediation appended by RiskNode for
              # HIGH/CRITICAL CVE findings. Always backed by a separate
              # LLM_INFERENCE citation (distinct from the LLM_INFERENCE
              # citation on the Finding itself).
              "type": "monitor",
              "description": "Audit your codebase for custom Storage subclasses that override generate_filename(). If none exist, defer this finding. If any do, treat as version_bump priority.",
              "target_package": null,
              "target_version": null,
              "confidence": "low",
              "rationale": "Context-aware recommendation based on use_case=saas. Key factor: depends on custom Storage subclass usage. Reviewer should verify the analysis applies to their codebase before acting.",
              "tradeoffs": null,
              "citations": [
                {
                  "source": "llm_inference",
                  "url": null,
                  "identifier": null,
                  "excerpt": "Audit your codebase for custom Storage subclasses...",
                  "retrieved_at": "2026-05-13T14:32:09Z",
                  "confidence": "inferred",
                  "validated": false,
                  "validation_method": "not_validated",
                  "content_hash": "..."
                }
              ]
            }
          ],
          "citations": [
            {
              "source": "osv",
              "url": "https://osv.dev/vulnerability/GHSA-qm57-vhq3-3fwf",
              "identifier": "GHSA-qm57-vhq3-3fwf",
              "excerpt": "SQL injection via QuerySet methods on MySQL/MariaDB. CVSS 9.8.",
              "retrieved_at": "2026-05-13T14:32:08Z",
              "confidence": "authoritative",
              "validated": true,
              "validation_method": "api_response",
              "content_hash": "f7a8b9c0..."
            }
          ]
        }
        # ... remaining CVE findings
      ]
    }

RESPONSE 404 Not Found:
    { "error": "job_not_found", "message": "No scan job found with id ..." }

# Note: prior versions returned 409 "scan_in_progress" mid-scan. That
# behavior is removed — the endpoint now serves a partial view from
# live graph state and tags it with scan_status != "complete". 404 is
# only returned when job_id is genuinely unknown.


# =============================================================================
# GET /scan/risk-matrix/{job_id}
# =============================================================================
# Two response shapes in one endpoint, controlled by ?view= query param.
#
# ?view=grouped  (default) — one row per package, both risk dimensions
#                            → drives the risk matrix dashboard table
#
# ?view=flat               — one row per finding, sorted by severity desc
#                            → drives the findings inbox / list view
#
# Both shapes echo use_case at the top level AND per-row for auditability.
#
# IDEMPOTENT ACROSS LIFECYCLE: same as /scan/results, this endpoint
# serves a partial view synthesized from live graph state when scan is
# "running" or "awaiting_human", and a final view from the stored
# report when "complete". The response carries a `scan_status` field
# (same vocabulary as /scan/status) so the UI can label partial data
# accordingly.
#
# For partial views (scan_status != "complete"):
#   - rows[] / findings[] reflect packages and findings analyzed so far
#   - dependency_chain is populated normally
#   - contextualized_severity / contextualization_rationale appear
#     for any HIGH/CRITICAL CVE finding that RiskNode has already
#     processed
# -----------------------------------------------------------------------------

REQUEST:
  Method: GET
  Path:   /scan/risk-matrix/{job_id}
  Query params:
    view: "grouped" | "flat"   (default: "grouped")

RESPONSE 200 OK — ?view=grouped:
    {
      "job_id": "job-8f2c1a9b-...",
      "scan_status": "complete",
        # "running" | "awaiting_human" | "complete" | "failed"
      "use_case": "saas",
        # Echoed. This is the lens through which ALL risk was evaluated.
        # Frontend: show as a badge/pill near the table header.
        # e.g. "Risk evaluated as: SaaS application"

      "scanned_at": "2026-05-13T14:32:00Z",

      "summary": {
        "total_packages": 108,
        "packages_with_findings": 7,
        "packages_clean": 101,
        "critical_count": 2,
        "high_count": 2,
        "medium_count": 3,
        "low_count": 0,
        "awaiting_review_count": 3
      },

      "rows": [
        # One row per package. Sorted: highest combined severity first.
        # Packages with no findings are included (license_risk: "none",
        # security_risk: "none") — proves we checked everything.
        # Frontend can offer "show clean packages" toggle.
        {
          "package": "django",
          "version": "4.2.3",
          "transitive": false,
          "use_case": "saas",
            # Per-row use_case echo — makes export/CSV unambiguous.
          "license_risk": "none",
          "security_risk": "critical",
          "overall_status": "human_review",
            # Highest-priority decision_status across all findings for this pkg.
            # "human_review" > "auto_remediate" > "auto_accepted" > "clean"
          "finding_count": 2,
            # Total number of findings for this package.
          "finding_ids": ["f-7d8e9f0a-...", "f-2b3c4d5e-..."],
            # IDs to fetch full finding detail from /scan/results
          "action_label": "Review CVEs",
            # Short suggested action for the Action column.
            # Generated by backend based on finding types + decision_status.
            # Values: "Review CVEs" | "Review License" | "Two-track review" |
            #         "Auto-remediated" | "Accepted" | "Clean"
          "has_fix_available": true,
            # True if any finding has a VERSION_BUMP or PACKAGE_SWAP remediation.
            # Drives a "Fix available" badge in the UI.
          "contextualized_severity": "low",
            # MAX contextualized_severity across any CVE finding on this
            # package. Populated only when a HIGH/CRITICAL CVE finding was
            # contextualized via LLM against the declared use_case. Null
            # when no contextualization ran. Routing still uses
            # max(raw, contextualized) — the LLM can never downgrade a
            # CRITICAL past the human-review gate.
          "contextualization_rationale": "Vulnerable code path requires a public image upload form, which this internal admin tool does not expose. Confidence: high.",
            # Rationale for the contextualized_severity above. Null when
            # no contextualization ran.
          "dependency_chain": ["factory-boy", "faker"]
            # The chain of parent packages that pulled this package into
            # the dependency tree, root-first, excluding the package itself.
            #   - []                              = direct dep (declared in
            #                                       requirements.txt)
            #   - ["factory-boy"]                 = 1 level transitive
            #   - ["factory-boy", "faker"]        = 2 levels transitive
            # Computed at API response time from raw_dependency_tree;
            # NOT stored on the Finding. Lowercased lookup, so the
            # `package` field in the row may be mixed-case (e.g. "Django")
            # while the chain entries are lowercased.
            # Drives "Why is this package in your tree?" UI affordance —
            # critical for surfacing buried transitive vulnerabilities.
        },
        {
          "package": "mysqlclient",
          "version": "2.1.1",
          "transitive": false,
          "use_case": "saas",
          "license_risk": "critical",
          "security_risk": "none",
          "overall_status": "human_review",
          "finding_count": 1,
          "finding_ids": ["f-3a7b9c2d-..."],
          "action_label": "Replace Package",
          "has_fix_available": true
        },
        {
          "package": "certifi",
          "version": "2024.2.2",
          "transitive": false,
          "use_case": "saas",
          "license_risk": "none",
          "security_risk": "none",
          "overall_status": "clean",
          "finding_count": 0,
          "finding_ids": [],
          "action_label": "Clean",
          "has_fix_available": false
        }
        # ... remaining packages
      ]
    }

RESPONSE 200 OK — ?view=flat:
    {
      "job_id": "job-8f2c1a9b-...",
      "scan_status": "complete",
        # "running" | "awaiting_human" | "complete" | "failed"
      "use_case": "saas",
      "scanned_at": "2026-05-13T14:32:00Z",

      "findings": [
        # All findings, flat list, sorted severity desc then by package name.
        # One finding per row — a package with 3 CVEs = 3 rows.
        {
          "finding_id": "f-7d8e9f0a-...",
          "package": "django",
          "version": "4.2.3",
          "finding_type": "cve",
          "severity": "critical",
          "use_case": "saas",
          "description": "CVE-2024-42005: SQL injection via QuerySet methods.",
          "recommendation": "Upgrade to Django 4.2.14.",
          "decision_status": "human_review",
          "transitive": false,
          "has_fix_available": true,
          "fix_version": "4.2.14",
            # Null if no version bump available.
          "citation_count": 1,
            # How many citations back this finding. Drives a "Cited" badge.
          "primary_citation_source": "osv",
            # Source type of the highest-confidence citation.
          "contextualized_severity": "low",
            # Lowercase RiskLevel value (or null). Populated by RiskNode
            # for HIGH/CRITICAL CVE findings only. Always null for
            # license findings and for LOW/MEDIUM CVE findings.
            # Routing uses max(severity, contextualized_severity) — the
            # LLM-derived downgrade NEVER bypasses the human-review gate
            # when the raw severity is HIGH/CRITICAL.
          "contextualization_rationale": "One-sentence LLM reasoning. Confidence: high.",
            # Companion to contextualized_severity. Null when no
            # contextualization ran. Backed by an LLM_INFERENCE citation
            # appended to the finding's citations list.
          "dependency_chain": ["factory-boy", "faker"]
            # Same shape and semantics as in the grouped view above —
            # root-first list of parent packages, [] for direct deps.
        }
        # ... remaining findings
      ]
    }


# =============================================================================
# GET /scan/pending-review/{job_id}
# =============================================================================
# Returns only the findings currently awaiting human decision.
# Frontend polls this when status = "awaiting_human".
# Each finding includes the full detail needed for the review UI,
# including prior_decision if an L2 memory hit exists.
# -----------------------------------------------------------------------------

REQUEST:
  Method: GET
  Path:   /scan/pending-review/{job_id}

RESPONSE 200 OK:
    {
      "job_id": "job-8f2c1a9b-...",
      "use_case": "saas",
        # Echoed. Reviewer sees the use_case context before making decisions.
      "pending_count": 3,

      "findings": [
        # Full finding objects for human review. Sorted severity desc.
        # Each includes prior_decision if L2 memory hit found.
        {
          "finding_id": "f-7d8e9f0a-...",
          "package": "django",
          "version": "4.2.3",
          "finding_type": "cve",
          "severity": "critical",
          "use_case": "saas",
          "description": "CVE-2024-42005: SQL injection...",
          "recommendation": "Upgrade to Django 4.2.14.",
          "decision_status": "human_review",
          "remediations": [ "... full remediation objects ..." ],
          "citations": [ "... full citation objects ..." ],
          "prior_decision": null,
            # If non-null, L2 memory hit. Shape:
            # {
            #   "decided_at": "2026-03-15T09:41:00Z",
            #   "decided_by": "jane.doe@org.com",
            #   "decision_status": "accepted",
            #   "rationale": "Vulnerable code path not exposed to user input.",
            #   "l2_mode": "show_for_confirmation"
            #     # The mode from POLICY.yml for this severity level.
            #     # Frontend uses this to determine UI behavior:
            #     #   always_resurface      → show finding fresh, no shortcuts
            #     #   show_for_confirmation → show "Confirm previous" button
            #     #   auto_accept_with_log  → (never reaches this endpoint)
            # }
          "dependency_chain": ["factory-boy", "faker"]
            # Root-first list of parent packages that pulled this
            # package in. [] for direct deps. Same shape as in the
            # risk-matrix grouped/flat views. Lowercased entries.
        }
        # ... remaining pending findings
      ]
    }

RESPONSE 200 OK (nothing pending):
    {
      "job_id": "job-8f2c1a9b-...",
      "use_case": "saas",
      "pending_count": 0,
      "findings": []
    }


# =============================================================================
# POST /scan/decision/{finding_id}
# =============================================================================
# Submit a human decision for a pending finding.
# Resumes the LangGraph pipeline after the HITL interrupt.
# If this was the last pending finding, the graph proceeds to AuditNode.
# -----------------------------------------------------------------------------

REQUEST:
  Method: POST
  Path:   /scan/decision/{finding_id}
  Headers:
    Content-Type: application/json

  Body:
    {
      "job_id": "job-8f2c1a9b-...",
        # Required. Identifies which scan this decision belongs to.

      "decision_status": "accepted",
        # Required. "accepted" | "deferred" | "auto_remediate"

      "rationale": "Vulnerable code path (QuerySet.annotate) is not used in our codebase. Upgrading Django is scheduled for next sprint.",
        # Required when decision_status is "accepted" or "deferred".
        # Null is rejected for accepted/deferred — rationale is mandatory
        # for audit trail completeness.
        # Null is fine for "auto_remediate" (no human rationale needed).

      "decided_by": "kaden.godinez@org.com"
        # Required. User identifier. Free-form string for v1.
        # v2: validated against org's user directory.
    }

RESPONSE 200 OK:
    {
      "finding_id": "f-7d8e9f0a-...",
      "job_id": "job-8f2c1a9b-...",
      "use_case": "saas",
        # Echoed. Decision is recorded as having been made under this use_case.
      "decision_status": "accepted",
      "decided_by": "kaden.godinez@org.com",
      "decided_at": "2026-05-13T14:45:22Z",
      "pending_remaining": 2,
        # How many findings are still pending for this job.
        # Frontend uses this to update the pending review counter.
        # When 0, the scan is proceeding to finalization.
      "graph_status": "awaiting_human"
        # Current graph status AFTER this decision was applied.
        # "awaiting_human" — more findings pending
        # "finalizing"     — this was the last finding; graph is proceeding
    }

RESPONSE 422 Unprocessable Entity (rationale required):
    {
      "error": "rationale_required",
      "message": "rationale is required when decision_status is 'accepted' or 'deferred'",
      "field": "rationale"
    }

RESPONSE 409 Conflict (finding already decided):
    {
      "error": "already_decided",
      "message": "Finding f-7d8e9f0a has already been decided (accepted).",
      "current_status": "accepted"
    }


# =============================================================================
# GET /audit/trail/{job_id}
# =============================================================================
# Returns the full hash-chained audit trail for a completed scan.
# For Ashu: surface this as an "Audit Log" tab or expandable section.
# Demo moment: "Every decision is recorded with cryptographic tamper evidence."
# -----------------------------------------------------------------------------

REQUEST:
  Method: GET
  Path:   /audit/trail/{job_id}

RESPONSE 200 OK:
    {
      "job_id": "job-8f2c1a9b-...",
      "use_case": "saas",
      "entry_count": 24,
      "chain_valid": true,
        # Pre-computed integrity check result.
        # True = hash chain is intact (no tampering detected).

      "entries": [
        {
          "seq": 0,
          "timestamp": "2026-05-13T14:32:00Z",
          "event_type": "scan_started",
          "payload": {
            "job_id": "job-8f2c1a9b-...",
            "use_case": "saas",
            "input_type": "requirements_file",
            "policy_hash": "sha256:a1b2c3..."
          },
          "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            # Genesis block — 64 zeros.
          "entry_hash": "3f4a5b6c7d8e9f0a..."
        },
        {
          "seq": 1,
          "timestamp": "2026-05-13T14:32:05Z",
          "event_type": "sbom_resolved",
          "payload": {
            "packages_total": 108,
            "packages_direct": 45,
            "packages_transitive": 63,
            "cache_hits": 34
          },
          "prev_hash": "3f4a5b6c7d8e9f0a...",
          "entry_hash": "b1c2d3e4f5a6b7c8..."
        },
        {
          "seq": 14,
          "timestamp": "2026-05-13T14:45:22Z",
          "event_type": "decision_made",
          "payload": {
            "finding_id": "f-7d8e9f0a-...",
            "package": "django",
            "version": "4.2.3",
            "finding_type": "cve",
            "severity": "critical",
            "use_case": "saas",
              # Decision context — use_case at time of decision.
            "decision_status": "accepted",
            "rationale": "Vulnerable code path not used. Upgrade scheduled.",
            "decided_by": "kaden.godinez@org.com",
            "decided_at": "2026-05-13T14:45:22Z",
            "citation_hashes": ["a1b2c3...", "d4e5f6..."]
              # content_hash values of citations backing this finding.
              # Cross-reference: if Citation in state has a different
              # content_hash, state was tampered with.
          },
          "prev_hash": "b1c2d3e4f5a6b7c8...",
          "entry_hash": "e7f8a9b0c1d2e3f4..."
        }
        # ... remaining entries
      ]
    }


# =============================================================================
# GET /audit/verify/{job_id}
# =============================================================================
# Independent integrity verification endpoint.
# Recomputes the full hash chain and all citation content hashes from scratch.
# Returns pass/fail with specifics on any tampering detected.
#
# Demo moment: "We can prove the audit trail hasn't been touched since it was
# written. Click verify — it recomputes every hash right now."
# -----------------------------------------------------------------------------

REQUEST:
  Method: GET
  Path:   /audit/verify/{job_id}

RESPONSE 200 OK:
    {
      "job_id": "job-8f2c1a9b-...",
      "verified_at": "2026-05-13T15:00:00Z",

      "chain_valid": true,
        # True = all entry hashes are consistent and chain is unbroken.
      "broken_at_seq": null,
        # If chain_valid is false: the seq number where the chain breaks.
        # Null when chain_valid is true.

      "citation_hashes_valid": true,
        # True = all Citation content_hashes match recomputed values.
      "citation_hash_mismatches": [],
        # List of mismatches if citation_hashes_valid is false. Shape:
        # [{ "finding_id": "f-...", "citation_index": 0,
        #    "stored_hash": "abc...", "computed_hash": "xyz..." }]

      "entries_verified": 24,
      "citations_verified": 31,

      "verdict": "PASS"
        # "PASS" — no tampering detected
        # "FAIL" — tampering detected, see broken_at_seq / citation_hash_mismatches
    }
