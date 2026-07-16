"""Deterministic fake external sink and downstream receipt reconciliation."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .canonical import canonical_digest, canonical_json
from .models import ConnectorExecutionContext, SideEffect
from .security import canonical_destination


class ReceiptError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class ReceiptStatus(StrEnum):
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    COMPENSATED = "COMPENSATED"


@dataclass(frozen=True, slots=True)
class FakeExternalReceipt:
    receipt_id: str
    transaction_id: str
    tenant_id: str
    connector_execution_id: str
    decision_id: str
    interaction_id: str
    arguments_hash: str
    side_effect: SideEffect
    destinations: tuple[str, ...]
    status: ReceiptStatus
    byte_count: int
    record_count: int
    occurred_at_epoch: float
    compensation_for: str | None = None


@dataclass(frozen=True, slots=True)
class ReceiptSummary:
    tenant_id: str
    connector_execution_id: str
    decision_id: str | None
    interaction_id: str | None
    arguments_hash: str | None
    observed_side_effect: SideEffect
    observed_destinations: tuple[str, ...]
    downstream_receipt_count: int
    byte_count: int
    record_count: int
    compensation_completed: bool


class FakeExternalReceiptStore:
    """Thread-safe simulation sink that stores evidence but performs no I/O."""

    def __init__(self) -> None:
        self._receipts: list[FakeExternalReceipt] = []
        self._lock = threading.RLock()

    def commit(
        self,
        context: ConnectorExecutionContext,
        *,
        side_effect: SideEffect,
        destinations: Sequence[str],
        byte_count: int,
        record_count: int = 1,
        transaction_id: str | None = None,
    ) -> FakeExternalReceipt:
        if side_effect in {SideEffect.NONE, SideEffect.READ}:
            raise ReceiptError(
                "INTERLOCK-RECEIPT-SIDE-EFFECT-INVALID",
                "external receipt requires a write side effect",
            )
        if byte_count < 0 or record_count <= 0:
            raise ReceiptError("INTERLOCK-RECEIPT-COUNT-INVALID", "receipt counts are invalid")
        try:
            canonical_destinations = tuple(canonical_destination(item) for item in destinations)
        except ValueError as error:
            raise ReceiptError(
                "INTERLOCK-RECEIPT-DESTINATION-INVALID",
                "receipt destination is invalid",
            ) from error
        if not canonical_destinations:
            raise ReceiptError(
                "INTERLOCK-RECEIPT-DESTINATION-MISSING",
                "external receipt needs at least one destination",
            )
        receipt = FakeExternalReceipt(
            receipt_id=str(uuid.uuid4()),
            transaction_id=transaction_id or str(uuid.uuid4()),
            tenant_id=context.tenant_id,
            connector_execution_id=context.connector_execution_id,
            decision_id=context.decision_id,
            interaction_id=context.interaction_id,
            arguments_hash=context.arguments_hash,
            side_effect=side_effect,
            destinations=canonical_destinations,
            status=ReceiptStatus.COMMITTED,
            byte_count=byte_count,
            record_count=record_count,
            occurred_at_epoch=time.time(),
        )
        with self._lock:
            if any(
                item.tenant_id == receipt.tenant_id
                and item.transaction_id == receipt.transaction_id
                and item.status == ReceiptStatus.COMMITTED
                for item in self._receipts
            ):
                raise ReceiptError(
                    "INTERLOCK-RECEIPT-TRANSACTION-DUPLICATE",
                    "transaction already has a committed receipt",
                )
            self._receipts.append(receipt)
        return receipt

    def compensate(
        self,
        *,
        tenant_id: str,
        transaction_id: str,
    ) -> FakeExternalReceipt:
        with self._lock:
            committed = next(
                (
                    item
                    for item in self._receipts
                    if item.tenant_id == tenant_id
                    and item.transaction_id == transaction_id
                    and item.status == ReceiptStatus.COMMITTED
                ),
                None,
            )
            if committed is None:
                raise ReceiptError(
                    "INTERLOCK-RECEIPT-TRANSACTION-NOT-FOUND",
                    "committed transaction was not found",
                )
            if any(
                item.compensation_for == committed.receipt_id
                and item.status == ReceiptStatus.COMPENSATED
                for item in self._receipts
            ):
                raise ReceiptError(
                    "INTERLOCK-RECEIPT-COMPENSATION-DUPLICATE",
                    "transaction was already compensated",
                )
            receipt = FakeExternalReceipt(
                receipt_id=str(uuid.uuid4()),
                transaction_id=str(uuid.uuid4()),
                tenant_id=committed.tenant_id,
                connector_execution_id=committed.connector_execution_id,
                decision_id=committed.decision_id,
                interaction_id=committed.interaction_id,
                arguments_hash=committed.arguments_hash,
                side_effect=committed.side_effect,
                destinations=committed.destinations,
                status=ReceiptStatus.COMPENSATED,
                byte_count=0,
                record_count=committed.record_count,
                occurred_at_epoch=time.time(),
                compensation_for=committed.receipt_id,
            )
            self._receipts.append(receipt)
            return receipt

    def for_execution(
        self,
        tenant_id: str,
        connector_execution_id: str,
    ) -> tuple[FakeExternalReceipt, ...]:
        with self._lock:
            return tuple(
                item
                for item in self._receipts
                if item.tenant_id == tenant_id
                and item.connector_execution_id == connector_execution_id
            )

    def all(self, tenant_id: str) -> tuple[FakeExternalReceipt, ...]:
        with self._lock:
            return tuple(item for item in self._receipts if item.tenant_id == tenant_id)

    def summary(self, tenant_id: str, connector_execution_id: str) -> ReceiptSummary:
        receipts = self.for_execution(tenant_id, connector_execution_id)
        decision_ids = {item.decision_id for item in receipts}
        interaction_ids = {item.interaction_id for item in receipts}
        argument_hashes = {item.arguments_hash for item in receipts}
        if len(decision_ids) > 1 or len(interaction_ids) > 1 or len(argument_hashes) > 1:
            raise ReceiptError(
                "INTERLOCK-RECEIPT-BINDING-MISMATCH",
                "receipts for one execution have inconsistent decision binding",
            )
        committed = tuple(item for item in receipts if item.status == ReceiptStatus.COMMITTED)
        compensated_ids = {
            item.compensation_for
            for item in receipts
            if item.status == ReceiptStatus.COMPENSATED and item.compensation_for
        }
        side_effect = _strongest_side_effect(item.side_effect for item in committed)
        destinations = tuple(
            dict.fromkeys(destination for item in committed for destination in item.destinations)
        )
        return ReceiptSummary(
            tenant_id=tenant_id,
            connector_execution_id=connector_execution_id,
            decision_id=next(iter(decision_ids), None),
            interaction_id=next(iter(interaction_ids), None),
            arguments_hash=next(iter(argument_hashes), None),
            observed_side_effect=side_effect,
            observed_destinations=destinations,
            downstream_receipt_count=len(committed),
            byte_count=sum(item.byte_count for item in committed),
            record_count=sum(item.record_count for item in committed),
            compensation_completed=bool(committed)
            and all(item.receipt_id in compensated_ids for item in committed),
        )


DestinationResolver = Callable[[Mapping[str, Any]], Sequence[str]]
ResultFactory = Callable[[Mapping[str, Any], FakeExternalReceipt], Any]


class FakeExternalSinkConnector:
    """Receipt-aware Connector used for simulation without real external writes."""

    def __init__(
        self,
        store: FakeExternalReceiptStore,
        *,
        side_effect: SideEffect,
        destination_resolver: DestinationResolver,
        result_factory: ResultFactory | None = None,
        record_count: int = 1,
    ) -> None:
        if record_count <= 0:
            raise ValueError("record_count must be positive")
        self.store = store
        self.side_effect = side_effect
        self.destination_resolver = destination_resolver
        self.result_factory = result_factory
        self.record_count = record_count

    def execute_with_context(
        self,
        arguments: Mapping[str, Any],
        context: ConnectorExecutionContext,
    ) -> Any:
        destinations = tuple(self.destination_resolver(arguments))
        receipt = self.store.commit(
            context,
            side_effect=self.side_effect,
            destinations=destinations,
            byte_count=len(_canonical_bytes(arguments)),
            record_count=self.record_count,
        )
        if self.result_factory is not None:
            return self.result_factory(arguments, receipt)
        return {"status": "simulated", "transactionId": receipt.transaction_id}


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json(value)


def _strongest_side_effect(values) -> SideEffect:  # noqa: ANN001
    order = {
        SideEffect.NONE: 0,
        SideEffect.READ: 1,
        SideEffect.INTERNAL_WRITE: 2,
        SideEffect.EXTERNAL_WRITE: 3,
        SideEffect.PERMISSION_CHANGE: 4,
        SideEffect.PAYMENT: 5,
        SideEffect.DESTRUCTIVE_WRITE: 6,
    }
    strongest = SideEffect.NONE
    for value in values:
        if order[value] > order[strongest]:
            strongest = value
    return strongest
