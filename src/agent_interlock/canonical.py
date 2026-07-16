"""Versioned canonical JSON used for definitions, arguments, and events."""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

CANONICALIZER_VERSION = "interlock-c14n-v1"


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    if isinstance(value, Mapping):
        normalized_mapping = {}
        for key, item in value.items():
            normalized_key = str(_normalize(key))
            if normalized_key in normalized_mapping:
                raise ValueError(f"duplicate object key after Unicode normalization: {normalized_key!r}")
            normalized_mapping[normalized_key] = _normalize(item)
        return normalized_mapping
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite numbers are not valid canonical JSON")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json(value: Any, *, include_version: bool = False) -> bytes:
    normalized = _normalize(value)
    if include_version:
        normalized = {"canonicalizerVersion": CANONICALIZER_VERSION, "value": normalized}
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_digest(value: Any) -> str:
    return _sha256(canonical_json(value, include_version=True))


def raw_digest(value: bytes | str | Any) -> str:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _sha256(encoded)
