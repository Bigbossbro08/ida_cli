"""Small time-to-live cache for expensive IDB inventory scans.

``funcs_list`` / ``names_list`` / ``strings_list`` / ``classes_list`` re-walk the
whole database on every request. Caching the unfiltered scan for a short TTL
(and invalidating on mutations) removes that repeated cost for the common
"list then filter" pattern.

Dependency-free and importable outside IDA so it is unit-testable.
"""

import os
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def cache_ttl_seconds() -> float:
    return _env_float("IDA_CLI_CACHE_TTL_SEC", 60.0)


class TTLCache:
    """Thread-safe cache of computed values with a per-entry TTL."""

    def __init__(self, ttl: Optional[float] = None):
        self._lock = threading.Lock()
        self._items: Dict[str, Tuple[Any, float]] = {}
        self._ttl = ttl if ttl is not None else cache_ttl_seconds()
        self._hits = 0
        self._misses = 0

    @property
    def ttl(self) -> float:
        return self._ttl

    def get_or_set(self, key: str, producer: Callable[[], Any]) -> Any:
        now = time.monotonic()
        with self._lock:
            entry = self._items.get(key)
            if entry is not None and entry[1] > now:
                self._hits += 1
                return entry[0]
        value = producer()
        with self._lock:
            self._items[key] = (value, time.monotonic() + self._ttl)
            self._misses += 1
        return value

    def invalidate(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._items.clear()
            else:
                self._items.pop(key, None)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "keys": list(self._items.keys()),
                "hits": self._hits,
                "misses": self._misses,
                "ttl_seconds": self._ttl,
            }
