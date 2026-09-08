"""Shared approval store for external-write intents.

Both enforcement points -- the gateway and the SDK -- can hold an approval that binds an
approval id to an exact arguments hash, canonical destination set, and expiry for one
tenant. Extracted from the gateway so ``Interlock`` (the SDK) can grant and validate
approvals without duplicating the binding logic.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_digest
from .models import InvocationIntent
from .security import canonical_destination


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    tenant_id: str
    arguments_hash: str
    destinations: tuple[str, ...]
    expires_at_epoch: float
    approver: str


class ApprovalStore:
    def __init__(self) -> None:
        self._approvals: dict[str, Approval] = {}

    def grant(
        self,
        *,
        tenant_id: str,
        arguments: Mapping[str, Any],
        canonical_destinations: tuple[str, ...],
        approver: str,
        ttl_seconds: int = 300,
    ) -> Approval:
        approval = Approval(
            approval_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            arguments_hash=canonical_digest(arguments),
            destinations=canonical_destinations,
            expires_at_epoch=time.time() + ttl_seconds,
            approver=approver,
        )
        self._approvals[approval.approval_id] = approval
        return approval

    def find(self, tenant_id: str, arguments: Mapping[str, Any], destinations: tuple[str, ...]) -> Approval | None:
        """The unexpired approval bound to exactly these arguments and destinations, if one exists.

        This is how a caller that does not hold an approval id -- an adapter relaying a model's
        tool call -- still gets to use an approval an operator granted for that exact call.
        """
        try:
            canonical = tuple(canonical_destination(item) for item in destinations)
        except ValueError:
            return None
        arguments_hash = canonical_digest(arguments)
        now = time.time()
        for approval in self._approvals.values():
            if (
                approval.tenant_id == tenant_id
                and approval.arguments_hash == arguments_hash
                and approval.destinations == canonical
                and approval.expires_at_epoch >= now
            ):
                return approval
        return None

    def valid(self, intent: InvocationIntent, tenant_id: str, arguments: Mapping[str, Any]) -> bool:
        if not intent.approval_id:
            return False
        approval = self._approvals.get(intent.approval_id)
        try:
            destinations = tuple(canonical_destination(item) for item in intent.destinations)
        except ValueError:
            return False
        return bool(
            approval
            and approval.tenant_id == tenant_id
            and approval.arguments_hash == canonical_digest(arguments)
            and approval.destinations == destinations
            and approval.expires_at_epoch >= time.time()
        )
