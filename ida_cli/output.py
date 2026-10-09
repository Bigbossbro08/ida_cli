"""Response size limiting and downloadable full outputs.

Mirrors ida-pro-mcp's ``tools/call`` behaviour so the CLI and MCP paths agree:
when a response exceeds ``IDA_CLI_OUTPUT_LIMIT_CHARS``, the full payload is
cached under a UUID and a shape-preserving preview (long strings / long lists
truncated) is returned together with an ``output_id`` and a
``/output/<id>.json`` download URL.

Kept dependency-free (stdlib only) and importable outside IDA so it can be
unit-tested.
"""

import json
import os
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Optional, Tuple


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def output_limit_chars() -> int:
    return _env_int("IDA_CLI_OUTPUT_LIMIT_CHARS", 50000)


def preview_str_len() -> int:
    return _env_int("IDA_CLI_OUTPUT_PREVIEW_STR_LEN", 1000)


def preview_items() -> int:
    return _env_int("IDA_CLI_OUTPUT_PREVIEW_ITEMS", 10)


def cache_max_size() -> int:
    return _env_int("IDA_CLI_OUTPUT_CACHE_SIZE", 100)


def truncate_value(value: Any, depth: int = 0) -> Any:
    """Return a shape-preserving preview of ``value``.

    Long strings and long lists are cut down; dicts are recursed. Note (C2.4):
    list sentinels are intentionally not injected, to avoid breaking callers
    that assume homogeneous list item shapes.
    """
    if depth > 5:
        return value
    if isinstance(value, str) and len(value) > preview_str_len():
        return value[:preview_str_len()] + f"... [{len(value)} chars total]"
    if isinstance(value, list):
        return [truncate_value(item, depth + 1) for item in value[:preview_items()]]
    if isinstance(value, dict):
        return {k: truncate_value(v, depth + 1) for k, v in value.items()}
    return value


class OutputStore:
    """Thread-safe LRU store for full (untruncated) command outputs."""

    def __init__(self, max_size: Optional[int] = None):
        self._lock = threading.Lock()
        self._items: "OrderedDict[str, Any]" = OrderedDict()
        self._max = max_size if max_size and max_size > 0 else cache_max_size()

    def put(self, data: Any) -> str:
        output_id = str(uuid.uuid4())
        with self._lock:
            self._items[output_id] = data
            while len(self._items) > self._max:
                self._items.popitem(last=False)
        return output_id

    def get(self, output_id: str) -> Optional[Any]:
        with self._lock:
            return self._items.get(output_id)

    def limit(self, data: Any, download_base_url: Optional[str] = None) -> Tuple[Any, Optional[dict]]:
        """Return ``(maybe_truncated_data, meta_or_None)``.

        ``meta`` is None when the serialized payload is within budget.
        """
        try:
            serialized = json.dumps(data, default=str)
        except Exception:
            return data, None

        if len(serialized) <= output_limit_chars():
            return data, None

        output_id = self.put(data)
        base = (download_base_url or "").rstrip("/")
        download_url = f"{base}/output/{output_id}.json" if base else f"/output/{output_id}.json"
        meta = {
            "truncated": True,
            "total_chars": len(serialized),
            "output_id": output_id,
            "download_url": download_url,
        }
        return truncate_value(data), meta


OUTPUT_STORE = OutputStore()
