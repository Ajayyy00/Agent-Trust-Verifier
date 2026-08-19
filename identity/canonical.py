"""Deterministic payload serialization used by signing operations."""

import json
from collections.abc import Mapping
from typing import Any


def _without_excluded_keys(value: Any, exclude_keys: set[str] | frozenset[str]) -> Any:
    """Return a copied value with excluded mapping keys removed recursively."""
    if isinstance(value, Mapping):
        return {
            key: _without_excluded_keys(item, exclude_keys)
            for key, item in value.items()
            if key not in exclude_keys
        }
    if isinstance(value, list):
        return [_without_excluded_keys(item, exclude_keys) for item in value]
    if isinstance(value, tuple):
        return tuple(_without_excluded_keys(item, exclude_keys) for item in value)
    return value


def canonicalize(
    payload: dict[str, Any],
    exclude_keys: set[str] | frozenset[str] = frozenset({"signature"}),
) -> bytes:
    """Create stable bytes to prevent signature malleability across dict construction or serialization."""
    cleaned_payload = _without_excluded_keys(payload, exclude_keys)
    return json.dumps(
        cleaned_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
