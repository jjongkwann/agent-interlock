"""Tool definition registry with digest-pinned approval state."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Iterable

from .canonical import CANONICALIZER_VERSION, canonical_digest, raw_digest
from .models import DefinitionState, ToolDefinition


class InvalidStateTransition(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ToolRevision:
    revision_id: str
    tool_id: str
    definition: ToolDefinition
    canonical_digest: str
    raw_digest: str
    canonicalizer_version: str
    state: DefinitionState
    reason_codes: tuple[str, ...]
    observed_at: datetime
    approved_by: str | None = None
    approved_at: datetime | None = None


_METADATA_INSTRUCTION = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior)|read\s+.*(?:secret|credential|config|ssh)|"
    r"(?:send|upload|exfiltrat).*(?:secret|credential|file|config)|system\s+prompt|\.ssh/|mcp\.json)"
)


class DefinitionRegistry:
    """In-memory reference registry. Persistent adapters can mirror this contract."""

    def __init__(self) -> None:
        self._revisions: dict[str, ToolRevision] = {}
        self._by_tool: dict[str, list[str]] = {}

    def observe(self, definition: ToolDefinition, raw_definition: bytes | str | object | None = None) -> ToolRevision:
        digest = canonical_digest(definition.canonical_value())
        revision_id = f"{definition.tool_id}@{digest}"
        existing = self._revisions.get(revision_id)
        if existing:
            return existing

        reasons = list(self._inspect(definition))
        active = self.active_for(definition.tool_id)
        if reasons:
            state = DefinitionState.QUARANTINED
        elif active and active.canonical_digest != digest:
            state = DefinitionState.DRIFTED
            reasons.append("L1-M2-DEFINITION-DRIFT")
        else:
            state = DefinitionState.DISCOVERED

        revision = ToolRevision(
            revision_id=revision_id,
            tool_id=definition.tool_id,
            definition=definition,
            canonical_digest=digest,
            raw_digest=raw_digest(raw_definition if raw_definition is not None else definition.canonical_value()),
            canonicalizer_version=CANONICALIZER_VERSION,
            state=state,
            reason_codes=tuple(reasons),
            observed_at=datetime.now(UTC),
        )
        self._revisions[revision_id] = revision
        self._by_tool.setdefault(definition.tool_id, []).append(revision_id)
        return revision

    def approve(self, revision_id: str, approver: str) -> ToolRevision:
        revision = self.get(revision_id)
        if revision.state not in {
            DefinitionState.DISCOVERED,
            DefinitionState.QUARANTINED,
            DefinitionState.DRIFTED,
        }:
            raise InvalidStateTransition(f"cannot approve revision in {revision.state}")
        if not approver:
            raise ValueError("approver is required")
        return self._save(
            replace(
                revision,
                state=DefinitionState.APPROVED,
                approved_by=approver,
                approved_at=datetime.now(UTC),
            )
        )

    def activate(self, revision_id: str) -> ToolRevision:
        revision = self.get(revision_id)
        if revision.state != DefinitionState.APPROVED:
            raise InvalidStateTransition("only APPROVED revisions can become ACTIVE")
        current = self.active_for(revision.tool_id)
        if current and current.revision_id != revision_id:
            self._save(replace(current, state=DefinitionState.REVOKED))
        return self._save(replace(revision, state=DefinitionState.ACTIVE))

    def quarantine(self, revision_id: str, *reason_codes: str) -> ToolRevision:
        revision = self.get(revision_id)
        if revision.state in {DefinitionState.REJECTED, DefinitionState.REVOKED}:
            raise InvalidStateTransition(f"cannot quarantine revision in {revision.state}")
        reasons = tuple(dict.fromkeys((*revision.reason_codes, *reason_codes)))
        return self._save(replace(revision, state=DefinitionState.QUARANTINED, reason_codes=reasons))

    def reject(self, revision_id: str) -> ToolRevision:
        revision = self.get(revision_id)
        if revision.state != DefinitionState.QUARANTINED:
            raise InvalidStateTransition("only QUARANTINED revisions can be rejected")
        return self._save(replace(revision, state=DefinitionState.REJECTED))

    def revoke(self, revision_id: str) -> ToolRevision:
        revision = self.get(revision_id)
        if revision.state not in {DefinitionState.ACTIVE, DefinitionState.APPROVED}:
            raise InvalidStateTransition("only APPROVED or ACTIVE revisions can be revoked")
        return self._save(replace(revision, state=DefinitionState.REVOKED))

    def get(self, revision_id: str) -> ToolRevision:
        try:
            return self._revisions[revision_id]
        except KeyError as error:
            raise KeyError(f"unknown tool revision: {revision_id}") from error

    def active_for(self, tool_id: str) -> ToolRevision | None:
        return next(
            (self._revisions[item] for item in reversed(self._by_tool.get(tool_id, []))
             if self._revisions[item].state == DefinitionState.ACTIVE),
            None,
        )

    def revisions_for(self, tool_id: str) -> tuple[ToolRevision, ...]:
        return tuple(self._revisions[item] for item in self._by_tool.get(tool_id, []))

    def _save(self, revision: ToolRevision) -> ToolRevision:
        self._revisions[revision.revision_id] = revision
        return revision

    @staticmethod
    def _inspect(definition: ToolDefinition) -> Iterable[str]:
        if _METADATA_INSTRUCTION.search(definition.description):
            yield "L1-M1-METADATA-INSTRUCTION"
        description = definition.description.casefold()
        own_name = definition.tool_name.casefold()
        cross_ref = re.findall(r"(?:tool|server)\s+[`'\"]?([a-z0-9_.:/-]+)", description)
        if any(ref not in {own_name, definition.server_id.casefold()} for ref in cross_ref):
            yield "L1-M3-CROSS-SERVER-REFERENCE"

