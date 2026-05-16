# SignedOff Known Issues

This file tracks known limitations, bugs, and v1.1 polish opportunities
identified during v1 development. Issues are categorized by severity:

- **P0**: Demo blocker, fix immediately
- **P1**: Important but not demo-blocking, fix Sunday or after
- **P2**: Polish, fix opportunistically
- **P3**: Documented behavior / known limitation, don't fix

---

## P0 — Demo blockers

_(none open)_

---

## P1 — Fix soon

### P1 — Context-aware remediations have empty target_version

**Surface:** LLM contextualization recommendations sometimes mention specific
version numbers in their description (e.g. "Upgrade certifi to 2024.7.4 or
later"), but the structured `target_version` field on the context-aware
Remediation is `None` because the contextualization code in `risk_node.py`
doesn't extract version numbers from LLM prose.

**Impact:** UI can render the prose recommendation correctly, but cannot
populate a clean "Upgrade Available: X.Y.Z" badge or auto-PR target from the
context-aware Remediation's structured fields. Reviewers must read the prose
to see the recommended version.

**Reproduction:** Run `smoke_test.py` against `demo_requirements.txt` with
`use_case=saas`. Inspect `certifi 2024.2.2` contextualized findings — the
second remediation's description says "Upgrade certifi to 2024.7.4 or later"
but `target_version` is `None`.

**Fix path (v1.1):** Either ask the LLM to output a structured
`target_version` field alongside `contextualized_recommendation`, or do
post-hoc regex extraction from the description prose. LLM extraction is
cleaner. Estimated effort: 30 min.

---

### P1 — OSV version_bump remediation sometimes returns commit hash instead of release version

**Surface:** When OSV's `affected[].ranges` entry lists a fix as a commit SHA
(because no released version exists yet, or the fix is on `main`), the
`version_bump` remediation's `target_version` field contains the
40-character commit hash (e.g. `bd8153872e9c6fc98f4023df9c2deaffea2fa463`)
instead of a human-readable version number.

**Impact:** UI renders `Upgrade certifi from 2024.2.2 to bd8153872e9c...`
which is technically correct but useless to end users — nobody installs a
Python package by commit SHA in production.

**Reproduction:** Run `smoke_test.py` against `demo_requirements.txt`.
Inspect `certifi 2024.2.2` finding from OSV `PYSEC-2024-230` — the
`version_bump` remediation's `target_version` is a git hash.

**Fix path (v1.1):** In `nodes/cve_node.py`, detect when `target_version`
matches a SHA pattern (40 hex chars) and either:
- (a) drop the remediation entirely and emit a `no_fix_available`
  remediation with rationale "fix is on main but no released version yet", or
- (b) attempt to map the commit to a release tag via the package's GitHub API.

Option (a) is simpler. Estimated effort: 45 min.

---

## P2 — Polish

### P2 — UI rendering hint for dual same-type remediations

**Surface:** When a CVE finding's context-aware remediation comes back as
`version_bump` (the most common case), the Finding now has TWO remediations
of the same type:

- `remediations[0]`: `type=version_bump`, citation=`osv`, "Upgrade X to Y"
- `remediations[1]`: `type=version_bump`, citation=`llm_inference`, "Upgrade X to Y'"

The two are conceptually different (authoritative OSV fix vs LLM-suggested
recommendation, which may include alternatives like "or later"), but the UI
must avoid showing them as "Recommendation 1 of 2" and "Recommendation 2 of
2" — that's confusing.

**Impact:** Without UI distinction, reviewers see what looks like duplicate
recommendations.

**Fix path (UI):** Render remediations with citation-source-aware labels:
- OSV-cited remediation: "Authoritative fix (OSV registry)"
- LLM_INFERENCE-cited remediation: "Context-aware recommendation (analyzed
  for your use_case)"

Show citation badges (color-coded) to make the distinction immediately
visual. The CITATION SOURCE BADGES guide in the original UI spec already
defines these colors.

**Fix path (alternative — backend dedup):** If both remediations have the
same `type` AND `target_version`, collapse them into one with combined
citations. v1.1+.

---

## P3 — Documented behavior / won't fix

_(none open)_
