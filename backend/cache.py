import hashlib
import json
import time
from threading import Lock
from typing import Any, Dict, Optional


class TTLCache:
    """Thread-safe in-memory cache with TTL expiry."""

    def __init__(self, default_ttl: int = 3600):
        """Initialize cache.

        Args:
            default_ttl: Default time-to-live in seconds (default: 1 hour).
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._locks: Dict[str, Lock] = {}
        self._global_lock = Lock()
        self.default_ttl = default_ttl

    def _make_key(self, prefix: str, **kwargs: Any) -> str:
        """Create a deterministic cache key from prefix + sorted kwargs."""
        key_data = json.dumps(
            {"prefix": prefix, "params": dict(sorted(kwargs.items()))},
            sort_keys=True,
        )
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, prefix: str, ttl: Optional[int] = None, **kwargs: Any) -> Optional[Any]:
        """Get cached value if not expired.

        Args:
            prefix: Cache namespace (e.g. "shodan", "cve_search").
            ttl: Optional override for default TTL.
            **kwargs: Parameters to include in cache key.

        Returns:
            Cached value if found and not expired, None otherwise.
        """
        key = self._make_key(prefix, **kwargs)
        effective_ttl = ttl if ttl is not None else self.default_ttl

        with self._global_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if time.time() - entry["timestamp"] > effective_ttl:
                del self._cache[key]
                return None
            return entry["value"]

    def set(self, prefix: str, value: Any, ttl: Optional[int] = None, **kwargs: Any) -> None:
        """Set cached value with TTL.

        Args:
            prefix: Cache namespace.
            value: Value to cache (must be JSON-serializable).
            ttl: Optional override for default TTL.
            **kwargs: Parameters to include in cache key.
        """
        key = self._make_key(prefix, **kwargs)
        effective_ttl = ttl if ttl is not None else self.default_ttl

        with self._global_lock:
            self._cache[key] = {
                "prefix": prefix,
                "value": value,
                "timestamp": time.time(),
                "ttl": effective_ttl,
            }

    def clear(self, prefix: Optional[str] = None) -> int:
        """Clear cache entries.

        Args:
            prefix: If provided, clear only entries with this prefix.

        Returns:
            Number of entries cleared.
        """
        with self._global_lock:
            if prefix is None:
                count = len(self._cache)
                self._cache.clear()
                return count
            keys_to_delete = [
                key for key, entry in self._cache.items() if entry.get("prefix") == prefix
            ]
            for key in keys_to_delete:
                del self._cache[key]
            return len(keys_to_delete)
