"""Deterministic safety helpers for schemas, destinations, URLs, and secrets."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{8,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def contains_secret(value: Any) -> bool:
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in _SECRET_PATTERNS)
    if isinstance(value, Mapping):
        return any(contains_secret(item) for item in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_secret(item) for item in value)
    return False


def has_scannable_text(value: Any) -> bool:
    """Whether the secret scan has any subject at all: at least one non-empty string.

    contains_secret returns False for an argument map holding no strings, which is
    indistinguishable from a map that was scanned and came back clean. The coverage channel needs
    the two apart, so the traversal is mirrored here rather than folded into contains_secret --
    that one answers a security question and must stay a plain bool for sanitize_secrets' callers.
    """
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, Mapping):
        return any(has_scannable_text(item) for item in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(has_scannable_text(item) for item in value)
    return False


def sanitize_secrets(value: Any) -> tuple[Any, bool]:
    detected = False
    if isinstance(value, str):
        output = value
        for pattern in _SECRET_PATTERNS:
            output, count = pattern.subn("[REDACTED_SECRET]", output)
            detected = detected or count > 0
        return output, detected
    if isinstance(value, Mapping):
        output = {}
        for key, item in value.items():
            output[key], item_detected = sanitize_secrets(item)
            detected = detected or item_detected
        return output, detected
    if isinstance(value, list):
        output_list = []
        for item in value:
            clean, item_detected = sanitize_secrets(item)
            output_list.append(clean)
            detected = detected or item_detected
        return output_list, detected
    if isinstance(value, tuple):
        output_items = []
        for item in value:
            clean, item_detected = sanitize_secrets(item)
            output_items.append(clean)
            detected = detected or item_detected
        return tuple(output_items), detected
    return value, False


_SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {"type", "required", "properties", "additionalProperties", "items", "enum", "maxLength", "pattern"}
)
_IGNORED_SCHEMA_KEYWORDS = frozenset(
    {"description", "title", "default", "examples", "format", "x-interlock-destination"}
)


def unsupported_schema_keywords(schema: Mapping[str, Any]) -> tuple[str, ...]:
    """List, path-qualified, the keywords in ``schema`` that ``validate_schema`` ignores.

    Walks nested schemas through ``properties`` values and ``items``. Keywords in the
    subset ``validate_schema`` enforces are allowed, as are a handful of documentation
    and annotation keys it ignores harmlessly (``format`` is allowed because a future
    intent-derivation pass reads it). Anything else is reported as ``"<path>: <keyword>"``,
    e.g. ``"$.properties.to: minimum"``.
    """
    found: set[str] = set()

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, Mapping):
            return
        for keyword in node:
            if keyword not in _SUPPORTED_SCHEMA_KEYWORDS and keyword not in _IGNORED_SCHEMA_KEYWORDS:
                found.add(f"{path}: {keyword}")
        properties = node.get("properties")
        if isinstance(properties, Mapping):
            for name, sub_schema in properties.items():
                walk(sub_schema, f"{path}.properties.{name}")
        items = node.get("items")
        if items is not None:
            walk(items, f"{path}.items")
        additional_properties = node.get("additionalProperties")
        if isinstance(additional_properties, Mapping):
            walk(additional_properties, f"{path}.additionalProperties")

    walk(schema, "$")
    return tuple(sorted(found))


def validate_schema(value: Any, schema: Mapping[str, Any], path: str = "$") -> tuple[str, ...]:
    """Validate the security-relevant JSON Schema subset without a runtime dependency."""
    if not schema:
        return ()
    errors: list[str] = []
    expected = schema.get("type")
    type_map = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "null": type(None),
    }
    if expected in type_map and (
        not isinstance(value, type_map[expected]) or (expected in {"integer", "number"} and isinstance(value, bool))
    ):
        return (f"{path}: expected {expected}",)
    if expected == "object" and isinstance(value, Mapping):
        required = schema.get("required", [])
        errors.extend(f"{path}.{name}: required" for name in required if name not in value)
        properties = schema.get("properties", {})
        additional_properties = schema.get("additionalProperties")
        if additional_properties is False:
            errors.extend(f"{path}.{name}: additional property" for name in value if name not in properties)
        for name, sub_schema in properties.items():
            if name in value:
                errors.extend(validate_schema(value[name], sub_schema, f"{path}.{name}"))
        if isinstance(additional_properties, Mapping):
            for name in value:
                if name not in properties:
                    errors.extend(validate_schema(value[name], additional_properties, f"{path}.{name}"))
    if expected == "array" and isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            errors.extend(validate_schema(item, schema["items"], f"{path}[{index}]"))
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: not in enum")
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: exceeds maxLength")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: pattern mismatch")
    return tuple(errors)


def canonical_destination(value: str) -> str:
    raw = value.strip()
    if "@" in raw and "://" not in raw:
        local, domain = raw.rsplit("@", 1)
        if not local or not domain:
            raise ValueError("invalid email destination")
        return f"email:{local}@{domain.rstrip('.').encode('idna').decode('ascii').lower()}"
    parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    if not parsed.hostname:
        raise ValueError("destination must have a host")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme.lower()}://{host}{port}"


def destination_domain(canonical: str) -> str:
    if canonical.startswith("email:"):
        return canonical.rsplit("@", 1)[1]
    return urlsplit(canonical).hostname or ""


def validate_authorization_url(
    value: str,
    *,
    allowed_hosts: frozenset[str],
    allow_loopback: bool = False,
    resolve_dns: bool = False,
) -> tuple[bool, str | None]:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError):
        return False, "L1-M6-UNSAFE-AUTH-URL"
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return False, "L1-M6-UNSAFE-AUTH-URL"
    if host not in {item.rstrip(".").lower() for item in allowed_hosts}:
        return False, "L1-M6-UNSAFE-AUTH-URL"
    addresses: set[str] = set()
    try:
        addresses.add(str(ipaddress.ip_address(host.strip("[]"))))
    except ValueError:
        if resolve_dns:
            try:
                addresses.update(item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443))
            except OSError:
                return False, "L1-M6-UNSAFE-AUTH-URL"
    for address in addresses:
        ip = ipaddress.ip_address(address)
        unsafe = ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        if ip.is_loopback and allow_loopback:
            unsafe = False
        if unsafe:
            return False, "L1-M6-UNSAFE-AUTH-URL"
    return True, None
