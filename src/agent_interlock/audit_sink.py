"""Signed Audit Sink: promote an integrity-checked event into signed evidence.

The Ledger's ``integrity_hash`` is tamper-evident but keyless — anyone can
recompute it, so it proves nothing about origin. An Audit Sink that holds a
signing key seals each event with a detached keyed signature over its identity
and integrity hash. A verifier then knows the SINK vouched for that exact event,
which is the ``ENFORCED``/``RECONCILED`` evidence promotion docs/08 requires.

The signature is detached (a separate record), so the append-only Event schema
is unchanged. Asymmetric / KMS-backed keys and separate retention storage are
deferred; this is the reference symmetric-key sink.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .ledger import Event, verify_event
from .signing import sign_canonical, verify_canonical


class AuditSinkError(RuntimeError):
    """Raised when an event cannot be sealed or a seal cannot be trusted."""


@dataclass(frozen=True, slots=True)
class SignedAuditRecord:
    event_id: str
    tenant_id: str
    integrity_hash: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventId": self.event_id,
            "tenantId": self.tenant_id,
            "integrityHash": self.integrity_hash,
            "signature": self.signature,
        }


def _sealed_body(event_id: str, tenant_id: str, integrity_hash: str) -> Mapping[str, Any]:
    return {"eventId": event_id, "tenantId": tenant_id, "integrityHash": integrity_hash}


class SignedAuditSink:
    """Seals integrity-verified events with a keyed signature (detached evidence)."""

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("audit sink signing key must not be empty")
        self._key = key

    def seal(self, event: Event) -> SignedAuditRecord:
        if not verify_event(event):
            raise AuditSinkError("event failed integrity verification; refusing to sign")
        body = _sealed_body(event.event_id, event.tenant_id, event.integrity_hash)
        return SignedAuditRecord(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            integrity_hash=event.integrity_hash,
            signature=sign_canonical(body, self._key),
        )

    def verify(self, event: Event, record: SignedAuditRecord) -> bool:
        if record.event_id != event.event_id or record.tenant_id != event.tenant_id:
            return False
        if record.integrity_hash != event.integrity_hash:
            return False
        if not verify_event(event):
            return False
        body = _sealed_body(event.event_id, event.tenant_id, event.integrity_hash)
        return verify_canonical(body, record.signature, self._key)
