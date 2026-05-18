n7246g@US05CG025DS0P MINGW64 ~/OneDrive - Lockheed Martin US/Desktop/SignedOff (main)   
$ cat "C:/Users/N7246G/AppData/Local/Temp/sbom_fix_spec.md"
# SBOMNode Fix Spec: PyPI-Based Dependency Resolution

**Author:** Cascade recon session, 2026-05-18 11:15 UTC-7
**Target session:** Mac, 1300-1500 UTC-7 (90 min hard stop)
**Current tag:** `v1.0-render-deployed` (commit `1b4798a`)
**Reference:** `BUGS.md` section `## ROOT CAUSE - SBOMNode scans the server's own venv` 

---

## 1. PROBLEM STATEMENT

SBOMNode calls bare `subprocess.run(["pipdeptree", ...])` and
`subprocess.run(["pip-licenses", ...])` which introspect the server's
running Python environment. On Render, that environment is SignedOff's
own production venv (57 packages: aiohttp, anthropic, fastapi, etc.),
not the user's uploaded requirements.txt content (~45 direct packages:
Django, PyYAML, celery, etc.). The uploaded file is base64-decoded and
parsed for package names, but those names are only used to classify
pipdeptree output as direct vs transitive. The actual dependency tree
and license metadata come entirely from the wrong environment. See
`BUGS.md` ROOT CAUSE section for the full investigation trace.

---

## 2. SOLUTION OVERVIEW

For the `input_type="requirements_file"` code path in `sbom_node()`:

- **Parse** the uploaded requirements.txt to extract `(name, version)` pairs
- **Query** the PyPI JSON API for each package to get license metadata
- **Build** the `PackageRecord` list directly from PyPI responses
- **Remove** subprocess calls to pipdeptree and pip-licenses from this path
- **Transitive deps:** v1.1 scope. Only direct deps from requirements.txt
  are resolved. This replaces the old "scans server venv" limitation with
  a strictly better "direct deps only" limitation. All seeded demo findings
  are in direct deps, so the demo narrative is preserved.

No changes needed to `api.py`, `graph.py`, or `agent_state.py`. The
`PackageRecord` TypedDict schema is unchanged. State plumbing is correct.

---

## 3. IMPLEMENTATION PLAN

### Files to modify

| File | Changes |
|------|---------|
| `nodes/sbom_node.py` | New PyPI fetcher functions, rewrite sbom_node() body, remove dead subprocess code |
| `tests/test_sbom_node.py` | Update mocks from subprocess to PyPI, fix package count assertions, add new test cases |

### New functions to add in `nodes/sbom_node.py`

All signatures and docstrings below. Tonight-CC writes the bodies.

```python
PYPI_TIMEOUT_SECONDS = 15
PYPI_CONCURRENCY = 10


def parse_requirements_with_versions(requirements_text: str) -> list[tuple[str, Optional[str]]]:
    """
    Extract (package_name, pinned_version_or_None) from requirements text.

    Handles: == pins (captured), >=/>/<=/~=/!= constraints (name only),
    [extras] syntax, comments, blank lines, -r/-c/-e/--/git+/http lines.
    Deduplicates by lowercased name, first occurrence wins.

    Returns list of (name, version) tuples. version is None if not == pinned.
    """


async def _fetch_pypi_metadata(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    name: str,
    version: Optional[str],
) -> dict:
    """
    Query PyPI JSON API for a single package.

    Pinned:   GET https://pypi.org/pypi/{name}/{version}/json
    Unpinned: GET https://pypi.org/pypi/{name}/json (returns latest)

    Returns dict: name, version, license_raw, license_classifiers,
    success (bool), error (Optional[str]).

    Errors: 404 -> success=False. Timeout -> success=False.
    Network error -> success=False. Never raises.
    """


def _parse_classifier_to_license_string(classifier: str) -> str:
    """
    Extract license name from PyPI classifier.

    "License :: OSI Approved :: MIT License" -> "MIT License"
    "License :: OSI Approved :: BSD License" -> "BSD License"

    Takes the last segment after " :: " splitting.
    """


def _resolve_license_from_pypi(
    license_raw: Optional[str],
    license_classifiers: list[str],
) -> Optional[str]:
    """
    Best-effort SPDX license from PyPI metadata.

    Algorithm:
      1. license_raw non-empty AND len <= 100 -> normalize_license().
         If recognized, return it.
      2. Otherwise try first License :: classifier via
         _parse_classifier_to_license_string() -> normalize_license().
         If recognized, return it.
      3. Fallback: return raw value or None.
    """


async def _resolve_packages_from_pypi(
    parsed_requirements: list[tuple[str, Optional[str]]],
) -> tuple[list[dict], list[str]]:
    """
    Fetch metadata from PyPI for all packages, build PackageRecord list.

    Uses asyncio.Semaphore(PYPI_CONCURRENCY) + shared aiohttp.ClientSession.
    Pattern mirrors cve_node._enrich_vulns() (lines 477-498).

    Returns (list_of_PackageRecord_dicts, list_of_error_strings).
    """
```

### Functions to remove

| Function | Reason |
|----------|--------|
| `_run_pipdeptree()` | No longer called. Was the root cause of the bug. |
| `_run_pip_licenses()` | No longer called. Same subprocess-scanning issue. |
| `_flatten_tree()` | Only processed pipdeptree JSON tree output. |
| `PIPDEPTREE_TIMEOUT_SECONDS` | Replaced by `PYPI_TIMEOUT_SECONDS`. |
| `PIP_LICENSES_TIMEOUT_SECONDS` | Replaced by `PYPI_TIMEOUT_SECONDS`. |

Keep `parse_direct_package_names()` -- still importable, but the main
code path uses the new `parse_requirements_with_versions()` instead.

### Order of changes (smallest to largest)

1. Add SPDX map entries (section 4 below)
2. Add `_parse_classifier_to_license_string()`
3. Add `parse_requirements_with_versions()`
4. Add `_fetch_pypi_metadata()`
5. Add `_resolve_license_from_pypi()`
6. Add `_resolve_packages_from_pypi()`
7. Rewrite `sbom_node()` body for the requirements_file path
8. Remove dead functions
9. Update module docstring
10. Update tests

---

## 4. PYPI INTEGRATION SPECS

### Endpoint

```
GET https://pypi.org/pypi/{name}/{version}/json
```

No authentication. No observed rate limits at concurrency=10. All 63
demo packages resolved successfully in the spike.

### Concurrency pattern

Mirror the CVENode pattern from `nodes/cve_node.py` lines 477-498:

```python
import aiohttp

timeout = aiohttp.ClientTimeout(total=PYPI_TIMEOUT_SECONDS)
sem = asyncio.Semaphore(PYPI_CONCURRENCY)

async with aiohttp.ClientSession(timeout=timeout) as session:
    async def fetch_one(name, version):
        async with sem:
            # ... GET request, handle errors, return dict
            pass
    results = await asyncio.gather(*(fetch_one(n, v) for n, v in parsed))
```

### Error handling

| Scenario | Action |
|----------|--------|
| HTTP 404 | Skip package, append error string. Don't fail scan. |
| Timeout (15s) | Skip package, append error string. |
| Network error | Skip package, append error string. |
| ALL packages fail | Return `_failure("PyPI API unreachable for all packages")`. |     

### License resolution algorithm

```
Step 1: license_raw = info.get("license", "").strip()
Step 2: IF license_raw AND len(license_raw) <= 100:
          spdx, recognized = normalize_license(license_raw)
          IF recognized: RETURN spdx
Step 3: classifiers = [c for c in info["classifiers"] if c.startswith("License ::")]    
Step 4: IF classifiers:
          parsed = _parse_classifier_to_license_string(classifiers[0])
          spdx, recognized = normalize_license(parsed)
          IF recognized: RETURN spdx
Step 5: IF license_raw exists (even if unrecognized): RETURN license_raw
Step 6: RETURN None (LicenseNode handles as "unknown" downstream)
```

### New SPDX normalization map entries

Add to `LICENSE_NORMALIZATION` dict in `sbom_node.py`:

```python
"hpnd": "HPND",
"historical permission notice and disclaimer (hpnd)": "HPND",
"bsd-3-clause or apache-2.0": "BSD-3-Clause",
"apache-2.0 or mit": "Apache-2.0",
"lgpl with exceptions": "LGPL-2.1-or-later",
```

The following already exist in the map (no changes needed):
`"bsd license"`, `"apache software license"`, `"mit license"`.

---

## 5. PACKAGE RECORD SHAPE

Match the existing `PackageRecord` TypedDict exactly. No schema changes.

```python
record: PackageRecord = {
    "name":           pypi_name,        # canonical name from PyPI info.name
    "version":        pypi_version,     # from info.version
    "license":        resolved_spdx,    # from _resolve_license_from_pypi()
    "license_status": None,             # set downstream by LicenseNode
    "cves":           [],               # set downstream by CVENode
    "license_risk":   None,             # set downstream by RiskNode
    "security_risk":  None,             # set downstream by RiskNode
    "from_cache":     False,            # L1 cache check runs same as before
    "cached_at":      None,             # L1 cache check runs same as before
    "transitive":     False,            # everything from requirements.txt = direct     
}
```

### Direct vs transitive

- All packages parsed from the uploaded requirements.txt get `transitive=False`
- No transitive packages are included in v1.1
- L1 cache check logic is unchanged (runs after building the record)

### New v1.1 limitation docstring (replaces the old v1 limitation)

```
V1.1 LIMITATION (intentional, surfaced in errors[]):
    Only DIRECT dependencies declared in requirements.txt are resolved.
    Transitive dependencies are NOT included because the PyPI JSON API
    provides dependency names (requires_dist) but not fully resolved
    versions. Full transitive resolution requires pip's dependency
    resolver. v2 will add this via pip-compile dry-run or resolvelib.
```

Append to `errors[]` in every scan:

```python
errors.append(
    "v1.1 limitation: only direct dependencies from requirements.txt "
    "are resolved; transitive dependencies require a future version "
    "with full dependency resolution"
)
```

---

## 6. TEST CHANGES REQUIRED

### Existing tests that will break

| Test | Why it breaks | Fix |
|------|---------------|-----|
| `test_returns_normalized_package_records_with_full_typeddict_shape` | Mocks `subprocess.run`. New code uses aiohttp. Count changes from 5 to 2 (no transitive). | Mock `_resolve_packages_from_pypi` instead. Assert 2 packages. |
| `test_deduplicates_direct_and_transitive_with_direct_winning` | Dedup was based on pipdeptree tree position. No transitive packages now. | Rewrite: test duplicate lines in requirements.txt are deduplicated (PyYAML appears twice in demo file). |
| `test_pipdeptree_failure_marks_status_failed` | Tests pipdeptree CalledProcessError. pipdeptree no longer called. | Replace: test all PyPI lookups returning 404 -> status="failed". |
| `test_l1_cache_hit_increments_counter_and_populates_record` | Mocks subprocess. | Change mock target to `_resolve_packages_from_pypi`. Cache logic unchanged. |
| `test_include_transitive_false_filters_out_indirect_packages` | No transitive packages in new approach, so the filter is a no-op. | Rewrite: verify policy flag is respected (all direct -> all included regardless of flag). |

### Tests that will NOT break

All `normalize_license` tests, all `_detect_gpl_in_multi_license` tests,
`test_parse_direct_package_names_handles_common_formats` -- pure functions,
no subprocess dependency.

### New tests to add

```
test_parse_requirements_with_versions_pinned
  Input: "django==4.2.3\nrequests==2.28.0\n"
  Assert: [("django","4.2.3"), ("requests","2.28.0")]

test_parse_requirements_with_versions_unpinned
  Input: "django>=4.0\nflask\n"
  Assert: [("django",None), ("flask",None)]

test_parse_requirements_with_versions_extras_and_comments
  Input: "requests[security]==2.28.0\n# comment\n-r other.txt\n"
  Assert: [("requests","2.28.0")]

test_parse_requirements_with_versions_deduplicates
  Input: "PyYAML==5.4.1\nPyYAML==5.4.1\n"
  Assert: single entry

test_fetch_pypi_metadata_success
  Mock aiohttp 200 with Django JSON fixture. Assert success=True, fields populated.     

test_fetch_pypi_metadata_404
  Mock aiohttp 404. Assert success=False, error mentions 404.

test_fetch_pypi_metadata_timeout
  Mock asyncio.TimeoutError. Assert success=False.

test_resolve_license_clean_field
  license_raw="MIT", classifiers=[] -> "MIT"

test_resolve_license_empty_field_classifier_fallback
  license_raw="", classifiers=["License :: OSI Approved :: MIT License"] -> "MIT"       

test_resolve_license_full_text_classifier_fallback
  license_raw="<1000+ chars>", classifiers=["License :: OSI Approved :: BSD License"] -> "BSD-3-Clause"

test_resolve_license_multi_license_or
  license_raw="Apache-2.0 OR MIT", classifiers=[] -> "Apache-2.0"

test_sbom_node_uses_pypi_not_subprocess
  Mock _resolve_packages_from_pypi. Verify subprocess.run is never called.

test_sbom_node_all_pypi_failures_returns_failed
  Mock returning ([], ["error1","error2"]). Assert status="failed".

test_hpnd_normalization
  normalize_license("HPND") -> ("HPND", True)

test_lgpl_with_exceptions_normalization
  normalize_license("LGPL with exceptions") -> ("LGPL-2.1-or-later", True)
```

### Mocking strategy

Prefer mocking `_resolve_packages_from_pypi` at the function level
(same pattern as the existing `subprocess.run` mock). Return canned
PackageRecord lists and error lists. This avoids needing to mock
aiohttp internals in most tests. Reserve aiohttp-level mocks for
the `test_fetch_pypi_metadata_*` tests only.

---

## 7. ROLLBACK PLAN

### Current known-good state

```
Tag:    v1.0-render-deployed
Commit: 1b4798a
Branch: main
```

### Pre-fix tag (create before starting)

```bash
git tag -a v1.1-pre-sbom-fix -m "Pre SBOMNode PyPI fix"
git push origin v1.1-pre-sbom-fix
```

### If fix introduces regression

```bash
git revert HEAD --no-edit
git push origin main
# Render auto-deploys from main on push.
# If manual trigger needed: Render Dashboard -> Manual Deploy -> Deploy latest commit   
```

### Nuclear rollback

```bash
git reset --hard v1.0-render-deployed
git push origin main --force-with-lease
```

---

## 8. SMOKE TEST PROCEDURE (post-deploy)

### Setup

```bash
PAYLOAD=$(base64 -i demo_requirements.txt | tr -d '\n')
RENDER_URL="https://your-render-service.onrender.com"
```

### Test 1: Start scan

```bash
JOB=$(curl -s -X POST "$RENDER_URL/scan/start" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_type\": \"requirements_file\",
    \"input_value\": \"$PAYLOAD\",
    \"use_case\": \"saas\"
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")
echo "Job: $JOB"
```

### Test 2: Poll status until complete

```bash
for i in $(seq 1 20); do
  curl -s "$RENDER_URL/scan/status/$JOB" | python3 -c "
import sys, json; d = json.load(sys.stdin)
print(f\"Phase: {d['current_phase']}, Pkgs: {d['packages_total']}, Status: {d['status']}\")"
  sleep 5
done
```

**Expected:**
- `packages_total`: approximately **45** (direct deps only, not 57 or 151)
- `status`: should reach `awaiting_human`
- Should NOT take more than 30s for PyPI + OSV resolution

### Test 3: Verify package list content

```bash
curl -s "$RENDER_URL/scan/results/$JOB" | python3 -c "
import sys, json
pkgs = json.load(sys.stdin).get('packages', [])
names = sorted([p['name'].lower() for p in pkgs])
print(f'Total: {len(pkgs)}')
print(f'First 15: {names[:15]}')
# Must be present (demo direct deps):
for expected in ['django','requests','mysqlclient','cryptography','celery','boto3']:    
    assert expected in names, f'MISSING: {expected}'
# Must NOT be present (SignedOff server deps):
for bad in ['aiohttp','fastapi','anthropic','langgraph','langchain-core']:
    assert bad not in names, f'SERVER DEP LEAKED: {bad}'
print('PASS')
"
```

### Test 4: License data quality

```bash
curl -s "$RENDER_URL/scan/results/$JOB" | python3 -c "
import sys, json
pkgs = json.load(sys.stdin).get('packages', [])
with_lic = sum(1 for p in pkgs if p.get('license'))
print(f'License populated: {with_lic}/{len(pkgs)}')
without = [p['name'] for p in pkgs if not p.get('license')]
if without: print(f'Missing license: {without}')
"
```

**Expected:** 40+ of ~45 packages have license data.

### Test 5: LLM contextualization fires

```bash
curl -s "$RENDER_URL/scan/risk-matrix/$JOB?view=grouped" | python3 -c "
import sys, json
rows = json.load(sys.stdin).get('rows', [])
ctx = [r for r in rows if r.get('contextualized_severity')]
print(f'Contextualized: {len(ctx)}/{len(rows)}')
"
```

**Expected:** >0 contextualized rows (requires ANTHROPIC_API_KEY on Render).

### Test 6: Audit chain integrity (defer=True still works)

```bash
FINDING=$(curl -s "$RENDER_URL/scan/pending-review/$JOB" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['findings'][0]['finding_id'])")

curl -s -X POST "$RENDER_URL/scan/decision/$FINDING" \
  -H "Content-Type: application/json" \
  -d "{\"job_id\":\"$JOB\",\"decision_status\":\"accepted\",\"rationale\":\"smoke test\",\"decided_by\":\"smoke@test\"}"

curl -s "$RENDER_URL/audit/trail/$JOB" | python3 -c "
import sys, json; d = json.load(sys.stdin)
print(f'Seal: {d[\"seal_status\"]}')
assert d['seal_status'] == 'pending', 'FAIL: chain sealed after one decision!'
print('AUDIT OK')
"
```

---

## 9. KNOWN GOTCHAS FROM SPIKE

Results from running `sbom_spike.py` against all 63 unique packages
in `demo_requirements.txt`:

| Issue | Count | Impact | Mitigation |
|-------|-------|--------|------------|
| Full license text in `info.license` field | 2/63 (`django-admin-interface` 1.1KB, `pytest-django` 3.2KB) | Low | `len > 100` check, fall back to classifier. Both have clean classifiers. |
| Empty `info.license` field | 9/63 (`argon2-cffi`, `django-filter`, `httpx`, `marshmallow`, `pydantic`, `pydantic-settings`, `sqlparse`, `structlog`, `urllib3`) | Low | All 9 have clean `License ::` classifiers. Fallback handles them. |
| Multi-license "X OR Y" strings | 2/63 (`cryptography`: "BSD-3-Clause OR Apache-2.0", `orjson`: "Apache-2.0 OR MIT") | Low | Add to SPDX map. Both are permissive-OR-permissive. |
| HPND license identifier | 1/63 (`Pillow`) | Low | Add `"hpnd": "HPND"` to map. Valid SPDX ID, permissive. |
| "LGPL with exceptions" string | 1/63 (`psycopg2-binary`) | Low | Add to map as `LGPL-2.1-or-later`. Classifier confirms. |
| Unpinned versions resolve to latest | N/A in demo (all pinned) | Medium for real users | Document: recommend `pip freeze` output for accuracy. |
| No transitive deps | All scans | Medium | ~45 packages instead of ~110. All seeded findings are in direct deps. Document as v1.1 limitation. |
| PyPI name casing mismatch | Minor (`Faker` vs `faker`) | Low | Parser already lowercases for comparison. |

### Good news from spike

- 63/63 packages resolved (0 failures, 0 timeouts, 0 rate limits)
- No auth needed for PyPI JSON API
- Every package has at least one license signal (field or classifier)
- Existing `normalize_license()` handles ~90% of strings already

---

## 10. TIME BUDGET

| Step | Minutes | Cumulative |
|------|---------|------------|
| Read spec, orient, tag `v1.1-pre-sbom-fix` | 5 | 5 |
| SPDX map entries (HPND, LGPL-with-exceptions, OR patterns) | 5 | 10 |
| `_parse_classifier_to_license_string()` | 3 | 13 |
| `parse_requirements_with_versions()` | 8 | 21 |
| `_fetch_pypi_metadata()` | 10 | 31 |
| `_resolve_license_from_pypi()` | 8 | 39 |
| `_resolve_packages_from_pypi()` | 8 | 47 |
| Rewrite `sbom_node()` body | 10 | 57 |
| Remove dead functions + update docstring | 3 | 60 |
| Fix broken tests in `test_sbom_node.py` | 12 | 72 |
| Add new tests | 10 | 82 |
| `pytest` full suite | 3 | 85 |
| Commit, push, verify Render auto-deploy | 5 | 90 |
| **HARD STOP** | | **90 min** |

### If ahead of schedule

- Run full smoke test procedure (section 8)
- Mark BUGS.md ROOT CAUSE as RESOLVED
- Add edge case tests for classifier parsing

### If behind schedule (cut order)

1. Cut new edge-case parser tests (demo file is 100% == pinned)
2. Cut dead function removal (clutter but harmless)
3. **Never cut:** core functions + sbom_node rewrite + broken test fixes

---

## APPENDIX: Relevant PyPI JSON Response Fields

For `GET https://pypi.org/pypi/Django/4.2.3/json`, the `info` object
contains these fields we care about:

- `info.name` -> `"Django"` (canonical)
- `info.version` -> `"4.2.3"`
- `info.license` -> `"BSD-3-Clause"` (clean in this case)
- `info.classifiers` -> includes `"License :: OSI Approved :: BSD License"`
- `info.requires_dist` -> `["asgiref (<4,>=3.6.0)", "sqlparse (>=0.3.1)", ...]`
- `info.summary` -> short description string

Use this shape to build test fixtures for `test_fetch_pypi_metadata_success`.

### Test fixture template

```python
PYPI_DJANGO_FIXTURE = {
    "info": {
        "name": "Django",
        "version": "4.2.3",
        "license": "BSD-3-Clause",
        "classifiers": [
            "License :: OSI Approved :: BSD License",
            "Programming Language :: Python :: 3",
        ],
        "requires_dist": [
            "asgiref (<4,>=3.6.0)",
            "sqlparse (>=0.3.1)",
        ],
        "summary": "A high-level Python Web framework.",
    }
}
```
