"""Keyed signatures over canonical JSON for Audit Sink and sandbox attestation.

An ``integrity_hash`` (see :mod:`agent_interlock.canonical`) proves tamper-evidence:
anyone can recompute it. A signature proves ORIGIN — only a holder of the shared
key could have produced it, which is what promotes a claim to signed evidence.

The reference core uses stdlib HMAC-SHA256 with a symmetric key. Asymmetric /
KMS / HSM-backed signing for cross-boundary non-repudiation is a deferred extra.
"""

from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Any

from .canonical import canonical_json

ALGORITHM = "hmac-sha256"


def sign_canonical(value: Any, key: bytes) -> str:
    """Return ``hmac-sha256:<hex>`` over the canonical JSON encoding of ``value``."""
    if not key:
        raise ValueError("signing key must not be empty")
    digest = hmac.new(key, canonical_json(value), sha256).hexdigest()
    return f"{ALGORITHM}:{digest}"


def verify_canonical(value: Any, signature: str, key: bytes) -> bool:
    """Constant-time check that ``signature`` was produced by ``key`` over ``value``."""
    if not key or not isinstance(signature, str):
        return False
    try:
        expected = sign_canonical(value, key)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(signature, expected)
