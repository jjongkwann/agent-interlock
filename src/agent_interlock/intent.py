"""Derive what an invocation *actually* does from its arguments, schema and annotations.

A declared `InvocationIntent` is whatever the caller wrote. Every M9 control reads it, so on the
adoption path -- where the caller is an agent framework rather than a security-aware integrator --
the declaration is the one input an attacker-influenced model gets to choose. This module derives
the same two facts from evidence the caller did not author: the destinations named by properties
the *tool's* input schema marks as destinations, and the side effect the tool's own MCP annotations
assert. `INTERLOCK-INTENT-ARGUMENT-MISMATCH` compares the two against the declaration.

`ActorSpec.side_effects` is deliberately *not* a third source. That field is a capability
allowlist, and `policy._side_effect_declared` already reads it as one -- it permits
`SideEffect.NONE` against any target, whatever the target can do. Reading the same field as an
assertion about this invocation ("the strongest thing this tool can do is what it just did") makes
those two controls contradict each other on one field, and makes `NONE` unreachable for every tool
that declares a capability at all. `readOnlyHint` and `destructiveHint` carry no such ambiguity:
MCP defines them as statements about every call to the tool.

Pure functions, no I/O: this runs inside a check, on every invocation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .models import SideEffect

# JSON Schema `format` values that name a place data can be sent. `x-interlock-destination: true`
# is the escape hatch for a property that carries a destination in a shape `format` cannot express
# (a channel id, a queue name). Both are in security._IGNORED_SCHEMA_KEYWORDS, so a schema using
# them still passes definition-time validation.
DESTINATION_FORMATS = frozenset({"email", "uri", "hostname"})

# Severity, low to high. SideEffect is a StrEnum with no ordering of its own, and the check needs
# one to answer "is what this tool does worse than what the caller declared". PAYMENT and
# PERMISSION_CHANGE rank above DESTRUCTIVE_WRITE: both are externally visible and neither is
# undone by restoring data.
_SIDE_EFFECT_RANK = {
    SideEffect.NONE: 0,
    SideEffect.READ: 1,
    SideEffect.INTERNAL_WRITE: 2,
    SideEffect.EXTERNAL_WRITE: 3,
    SideEffect.DESTRUCTIVE_WRITE: 4,
    SideEffect.PAYMENT: 5,
    SideEffect.PERMISSION_CHANGE: 6,
}

_MISSING = object()


def side_effect_rank(effect: SideEffect | None) -> int:
    """Severity of one side effect, comparable with `<`. `None` -- nothing derived -- ranks below
    every member, so an absent derivation can never outrank a declaration."""
    if effect is None:
        return -1
    return _SIDE_EFFECT_RANK[effect]


@dataclass(frozen=True, slots=True)
class DerivedIntent:
    """What the evidence says, next to what the caller declared.

    `destinations` holds the raw argument strings, not canonical ones: canonicalisation can fail,
    and a destination that fails to canonicalise is a finding rather than something to drop here.

    `derivable` is the difference between "looked and found nothing" and "there was nothing to look
    at". It is True when the schema marks at least one property as a destination, or when the
    annotations assert a side effect -- whether or not the arguments happened to fill those
    properties in. False makes the check INAPPLICABLE, which is what keeps a tool that marks
    nothing out of the RAN_CLEAN count instead of manufacturing a pass over no evidence.
    """

    destinations: tuple[str, ...]
    side_effect: SideEffect | None
    derivable: bool


def _marks_destination(schema: Mapping[str, Any]) -> bool:
    return schema.get("format") in DESTINATION_FORMATS or schema.get("x-interlock-destination") is True


def _string_values(value: Any) -> list[str]:
    """The strings at a marked property: one, or a list of them. A marked property holding anything
    else names no destination this pass can read, and silently contributes none."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, str)]
    return []


def _walk(schema: Any, value: Any, found: list[str], marks: list[bool]) -> None:
    """Descend the schema and the arguments together, through `properties` and `items`.

    The value is carried alongside rather than walked on its own, because the schema is what says
    which position is a destination -- an argument map has no such marking. Descent continues past
    a missing value so that `marks` records the schema's marking either way.
    """
    if not isinstance(schema, Mapping):
        return
    if _marks_destination(schema):
        marks.append(True)
        if value is not _MISSING:
            found.extend(_string_values(value))
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        for name, sub_schema in properties.items():
            child = value[name] if isinstance(value, Mapping) and name in value else _MISSING
            _walk(sub_schema, child, found, marks)
    items = schema.get("items")
    if items is not None:
        if isinstance(value, list):
            for entry in value:
                _walk(items, entry, found, marks)
        else:
            _walk(items, _MISSING, found, marks)
    additional_properties = schema.get("additionalProperties")
    if isinstance(additional_properties, Mapping):
        names = properties if isinstance(properties, Mapping) else {}
        if isinstance(value, Mapping):
            for name, child in value.items():
                if name not in names:
                    _walk(additional_properties, child, found, marks)
        else:
            _walk(additional_properties, _MISSING, found, marks)


def _derive_side_effect(annotations: Mapping[str, Any]) -> SideEffect | None:
    """The tool's own account of what every call to it does.

    `destructiveHint` outranks `readOnlyHint` because a tool asserting both is contradicting
    itself, and the fail-closed reading of a contradiction is the destructive one.
    """
    if annotations.get("destructiveHint") is True:
        return SideEffect.DESTRUCTIVE_WRITE
    if annotations.get("readOnlyHint") is True:
        return SideEffect.READ
    return None


def derive_intent(
    arguments: Mapping[str, Any],
    input_schema: Mapping[str, Any],
    annotations: Mapping[str, Any],
) -> DerivedIntent:
    """Derive destinations and side effect from evidence the caller did not write."""
    found: list[str] = []
    marks: list[bool] = []
    _walk(input_schema, arguments, found, marks)
    fixed = annotations.get("interlock.fixedDestinations", ())
    if not isinstance(fixed, (list, tuple)) or any(not isinstance(item, str) or not item for item in fixed):
        raise ValueError("interlock.fixedDestinations must contain destination strings")
    found.extend(fixed)
    side_effect = _derive_side_effect(annotations)
    return DerivedIntent(
        # Deduplicated, order preserved: one property can be reached twice when an array schema and
        # its `items` are both marked, and the check emits one finding per destination.
        destinations=tuple(dict.fromkeys(found)),
        side_effect=side_effect,
        derivable=bool(marks) or bool(fixed) or side_effect is not None,
    )
