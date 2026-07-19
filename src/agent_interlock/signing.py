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
ED25519_ALGORITHM = "ed25519"


class SigningBackendUnavailable(RuntimeError):
    """Raised when asymmetric signing is requested without the crypto backend."""


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


def _require_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise SigningBackendUnavailable("asymmetric signing requires the 'jwt' extra (cryptography)") from None


def sign_canonical_ed25519(value: Any, private_key: bytes) -> str:
    """Return ``ed25519:<hex>`` over the canonical JSON encoding of ``value``.

    ``private_key`` is the 32-byte raw Ed25519 seed. This is the reference,
    in-process signer; a KMS/HSM signer produces the same ``ed25519:<hex>``
    format without the key ever leaving the boundary.
    """
    _require_cryptography()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(canonical_json(value))
    return f"{ED25519_ALGORITHM}:{signature.hex()}"


def verify_canonical_ed25519(value: Any, signature: str, public_key: bytes) -> bool:
    """Verify an ``ed25519:<hex>`` signature against a 32-byte raw public key."""
    if not public_key or not isinstance(signature, str):
        return False
    prefix = f"{ED25519_ALGORITHM}:"
    if not signature.startswith(prefix):
        return False
    _require_cryptography()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        raw = bytes.fromhex(signature[len(prefix) :])
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw, canonical_json(value))
        return True
    except (InvalidSignature, ValueError):
        return False
