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

import json
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .canonical import canonical_json, raw_digest
from .ledger import Event, verify_event
from .signing import sign_canonical, verify_canonical


class AuditSinkError(RuntimeError):
    """Raised when an event cannot be sealed or a seal cannot be trusted."""


class WORMViolation(AuditSinkError):
    """Raised when a write-once record is overwritten or the chain is broken."""


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


# --------------------------------------------------------------------------- #
# WORM (write-once-read-many) retention store
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class WORMEntry:
    """A sealed record fixed at a sequence position and chained to the prior one."""

    sequence: int
    record: SignedAuditRecord
    previous_hash: str
    entry_hash: str

    def canonical_value(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "record": self.record.to_dict(),
            "previousHash": self.previous_hash,
        }


_WORM_GENESIS = "sha256:" + "0" * 64


def _entry_hash(sequence: int, record: SignedAuditRecord, previous_hash: str) -> str:
    body = {"sequence": sequence, "record": record.to_dict(), "previousHash": previous_hash}
    return raw_digest(canonical_json(body))


class WORMAuditStore(Protocol):
    """Append-only retention for sealed audit records.

    A record, once appended, cannot be overwritten or removed; each entry is
    hash-chained to its predecessor so a deletion or reordering breaks
    verification. This is the storage contract; the reference implementation is
    in-process, and a durable backend (e.g. S3 Object Lock in compliance mode)
    satisfies the same contract.
    """

    def append(self, record: SignedAuditRecord) -> WORMEntry: ...

    def entries(self) -> tuple[WORMEntry, ...]: ...

    def verify_chain(self) -> bool: ...


class InMemoryWORMAuditStore:
    """Reference append-only, hash-chained store. No update or delete exists."""

    def __init__(self) -> None:
        self._entries: list[WORMEntry] = []
        self._seen: set[tuple[str, str]] = set()
        self._lock = threading.RLock()

    def append(self, record: SignedAuditRecord) -> WORMEntry:
        with self._lock:
            key = (record.tenant_id, record.event_id)
            if key in self._seen:
                raise WORMViolation("audit record already written; WORM store is append-only")
            previous_hash = self._entries[-1].entry_hash if self._entries else _WORM_GENESIS
            sequence = len(self._entries)
            entry = WORMEntry(
                sequence=sequence,
                record=record,
                previous_hash=previous_hash,
                entry_hash=_entry_hash(sequence, record, previous_hash),
            )
            self._entries.append(entry)
            self._seen.add(key)
            return entry

    def entries(self) -> tuple[WORMEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    def verify_chain(self) -> bool:
        with self._lock:
            return _verify_chain(self._entries)


def _verify_chain(entries: list[WORMEntry]) -> bool:
    previous_hash = _WORM_GENESIS
    for sequence, entry in enumerate(entries):
        if entry.sequence != sequence or entry.previous_hash != previous_hash:
            return False
        if entry.entry_hash != _entry_hash(sequence, entry.record, previous_hash):
            return False
        previous_hash = entry.entry_hash
    return True


def _record_from_dict(value: Mapping[str, Any]) -> SignedAuditRecord:
    return SignedAuditRecord(
        event_id=str(value["eventId"]),
        tenant_id=str(value["tenantId"]),
        integrity_hash=str(value["integrityHash"]),
        signature=str(value["signature"]),
    )


class FileWORMAuditStore:
    """File-backed append-only, hash-chained WORM store.

    Each entry is one JSONL line; the chain is verified when the file is opened
    (a tampered or truncated line raises), every append is flushed and fsynced,
    and the write-once dedupe survives a restart because the (tenant, event)
    keys are reloaded. Same contract as the in-memory store; durable object-lock
    (S3) remains a further step.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._entries: list[WORMEntry] = []
        self._seen: set[tuple[str, str]] = set()
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._path.parent.mkdir(parents=True, exist_ok=True)
            return
        entries: list[WORMEntry] = []
        with self._path.open("r", encoding="utf-8") as stream:
            for _line_number, line in enumerate(stream):
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                record = _record_from_dict(data["record"])
                entries.append(
                    WORMEntry(
                        sequence=int(data["sequence"]),
                        record=record,
                        previous_hash=str(data["previousHash"]),
                        entry_hash=str(data["entryHash"]),
                    )
                )
        if not _verify_chain(entries):
            raise WORMViolation(f"persisted WORM chain in {self._path} failed verification")
        self._entries = entries
        self._seen = {(entry.record.tenant_id, entry.record.event_id) for entry in entries}

    def append(self, record: SignedAuditRecord) -> WORMEntry:
        with self._lock:
            key = (record.tenant_id, record.event_id)
            if key in self._seen:
                raise WORMViolation("audit record already written; WORM store is append-only")
            previous_hash = self._entries[-1].entry_hash if self._entries else _WORM_GENESIS
            sequence = len(self._entries)
            entry = WORMEntry(
                sequence=sequence,
                record=record,
                previous_hash=previous_hash,
                entry_hash=_entry_hash(sequence, record, previous_hash),
            )
            self._persist(entry)
            self._entries.append(entry)
            self._seen.add(key)
            return entry

    def _persist(self, entry: WORMEntry) -> None:
        line = json.dumps(
            {**entry.canonical_value(), "entryHash": entry.entry_hash},
            ensure_ascii=False,
            sort_keys=True,
        )
        with self._path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def entries(self) -> tuple[WORMEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    def verify_chain(self) -> bool:
        with self._lock:
            return _verify_chain(self._entries)
