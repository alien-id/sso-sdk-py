"""Canonical JSON: keys sorted recursively, no whitespace, UTF-8 (no \\uXXXX).

Mirrors the JS `canonicalJSONString` in `@alien-id/sso-agent-id`. Required
because the agent token's signature covers `JSON.stringify(sortValue(payload))`
of an object with sorted keys — any deviation breaks the signature.
"""

from __future__ import annotations

import json
from typing import Any


def _sort_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_sort_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _sort_value(value[k]) for k in sorted(value.keys())}
    return value


def canonical_json_string(value: Any) -> str:
    return json.dumps(_sort_value(value), separators=(",", ":"), ensure_ascii=False)


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json_string(value).encode("utf-8")
