"""
cache/l1_package_cache.py
=========================
L1 Package Cache — in-memory, keyed by (package_name, version).

Stores license metadata and raw CVE records per package so that
repeated scans of the same packages don't re-hit PyPI or OSV APIs.

Key:   f"{name.lower()}=={version}"   e.g. "requests==2.28.0"
Value: partial PackageRecord fields that are safe to cache
       (license, cves, cached_at — NOT risk levels, which are
       use-case-dependent and must be recomputed per scan)

TTL: entries are stamped with cached_at. Actual eviction is v2.
     For v1, the cache never evicts — it's a process-lifetime dict.
     cached_at is stored now so v2 TTL enforcement is a one-liner add.

Thread safety: a single asyncio event loop owns this process.
     No locking needed for v1 (single-process, async concurrency).
     v2 (multi-worker): replace with Redis or shared Postgres table.

Surfaced in UI as: "X of Y packages served from cache"
This is a key demo metric — shows latency savings to judges.
"""

from datetime import datetime, timezone
from typing import Optional


class L1PackageCache:
    """
    In-memory L1 cache for per-package license and CVE data.

    Lifecycle:
        - SBOMNode checks cache before resolving packages
        - LicenseNode and CVENode write to cache after fetching
        - Cache persists for the lifetime of the process (v1)
        - Pre-warmed from demo_cache.json at startup (stretch goal)
    """

    def __init__(self):
        self._store: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Cache key
    # ------------------------------------------------------------------

    @staticmethod
    def make_key(name: str, version: str) -> str:
        """
        Canonical cache key. Lowercased name for case-insensitive lookup.
        PyPI package names are case-insensitive (Pillow == pillow).

        >>> L1PackageCache.make_key("Pillow", "9.5.0")
        'pillow==9.5.0'
        """
        return f"{name.lower()}=={version}"

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, name: str, version: str) -> Optional[dict]:
        """
        Retrieve a cached package record.

        Returns the cached dict if found, None if not cached.
        Callers check `from_cache` on the returned dict — it is always
        True here (that's the point of the cache).

        Usage in SBOMNode:
            cached = l1_cache.get(pkg_name, pkg_version)
            if cached:
                record["license"] = cached["license"]
                record["cves"] = cached["cves"]
                record["from_cache"] = True
                record["cached_at"] = cached["cached_at"]
        """
        return self._store.get(self.make_key(name, version))

    def has(self, name: str, version: str) -> bool:
        """Check existence without retrieving the full record."""
        return self.make_key(name, version) in self._store

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def set(
        self,
        name: str,
        version: str,
        license: Optional[str] = None,
        cves: Optional[list] = None,
    ) -> None:
        """
        Store or update a package's cached data.

        Only caches fields that are safe to reuse across scans:
          - license: SPDX identifier (doesn't change between scans)
          - cves: raw OSV response (changes only when new CVEs disclosed)

        Does NOT cache:
          - license_risk / security_risk: use-case-dependent, recomputed
            per scan. Caching these would give wrong results if a user
            runs two scans with different use_case values.
          - decision_status: per-scan decision, never shared.

        Args:
            name:    Package name (case-insensitive, normalized internally)
            version: Exact version string e.g. "2.28.0"
            license: SPDX license identifier or None if unknown
            cves:    List of raw OSV vulnerability dicts, [] if clean
        """
        key = self.make_key(name, version)
        existing = self._store.get(key, {})

        self._store[key] = {
            # Preserve existing values if new values are None
            # (allows partial updates — CVENode can update cves without
            # overwriting license that LicenseNode already cached)
            "name": name.lower(),
            "version": version,
            "license": license if license is not None else existing.get("license"),
            "cves": cves if cves is not None else existing.get("cves", []),
            "cached_at": existing.get("cached_at") or datetime.now(timezone.utc).isoformat(),
            "from_cache": True,
        }

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def warm_from_dict(self, data: dict[str, dict]) -> int:
        """
        Pre-warm the cache from a dict of pre-fetched package data.

        Used at startup to load demo_cache.json (stretch goal) or any
        pre-built cache snapshot.

        Args:
            data: Dict mapping cache keys to cached records.
                  Keys must be in "name==version" format.
                  Values must have: license, cves, cached_at fields.

        Returns:
            Number of entries loaded.

        Usage:
            import json
            with open("data/demo_cache.json") as f:
                l1_cache.warm_from_dict(json.load(f))
        """
        loaded = 0
        for key, record in data.items():
            # Validate minimal shape before loading
            if not isinstance(record, dict):
                continue
            if "==" not in key:
                continue
            self._store[key] = {
                "name": record.get("name", key.split("==")[0]),
                "version": record.get("version", key.split("==")[1]),
                "license": record.get("license"),
                "cves": record.get("cves", []),
                "cached_at": record.get("cached_at", datetime.now(timezone.utc).isoformat()),
                "from_cache": True,
            }
            loaded += 1
        return loaded

    def export(self) -> dict[str, dict]:
        """
        Export the full cache as a serializable dict.
        Use this to snapshot the cache to demo_cache.json after a demo run.

        Usage:
            import json
            with open("data/demo_cache.json", "w") as f:
                json.dump(l1_cache.export(), f, indent=2)
        """
        return dict(self._store)

    # ------------------------------------------------------------------
    # Stats (surfaced in /scan/status as cache_hits)
    # ------------------------------------------------------------------

    def size(self) -> int:
        """Total number of cached entries."""
        return len(self._store)

    def clear(self) -> None:
        """Clear all cached entries. Used in tests."""
        self._store.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# Imported by SBOMNode, LicenseNode, CVENode.
# One cache instance per process lifetime.
# ---------------------------------------------------------------------------
l1_cache = L1PackageCache()
