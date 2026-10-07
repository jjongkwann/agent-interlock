"""Process-local, one-use approvals bound to an exact invocation and installed policy."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .canonical import canonical_digest
from .models import InvocationIntent, LinkPolicy
from .security import canonical_destination


def approval_binding(
    *, tenant_id: str, source_actor_id: str, target_actor_id: str, revision_id: str | None,
    policy: LinkPolicy, intent: InvocationIntent, arguments: Mapping[str, Any],
) -> str:
    intent_values = asdict(intent)
    del intent_values["approval_id"]
    intent_values["destinations"] = sorted({canonical_destination(item) for item in intent.destinations})
    return canonical_digest({
        "tenant": tenant_id, "source": source_actor_id, "target": target_actor_id, "revision": revision_id,
        "policy": {key: sorted(value) if isinstance(value, frozenset) else value
                   for key, value in asdict(policy).items()},
        "intent": {key: sorted(value) if isinstance(value, frozenset) else value
                   for key, value in intent_values.items()},
        "arguments": arguments,
    })


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    binding_hash: str
    expires_at_epoch: float
    approver: str


class ApprovalStore:
    def __init__(self) -> None:
        self._approvals: dict[str, Approval] = {}
        self._lock = threading.Lock()

    def grant(self, *, binding_hash: str, approver: str, ttl_seconds: int = 300) -> Approval:
        if not approver.strip() or ttl_seconds <= 0:
            raise ValueError("approver and positive approval TTL are required")
        approval = Approval(str(uuid.uuid4()), binding_hash, time.time() + ttl_seconds, approver)
        with self._lock:
            self._approvals[approval.approval_id] = approval
        return approval

    def find(self, binding_hash: str) -> Approval | None:
        with self._lock:
            return next((approval for approval in self._approvals.values()
                         if approval.binding_hash == binding_hash and approval.expires_at_epoch > time.time()), None)

    def valid(self, approval_id: str | None, binding_hash: str, *, consume: bool = False) -> bool:
        """Consumption is atomic and happens before execution, including a failed execution.

        Evaluation and observation never spend an approval. A spent grant cannot authorize a
        second operation; gateway retries use the original idempotency result instead.
        """
        with self._lock:
            approval = self._approvals.get(approval_id)
            if not approval or approval.binding_hash != binding_hash or approval.expires_at_epoch <= time.time():
                return False
            if consume:
                del self._approvals[approval.approval_id]
            return True
