"""Bounded, reviewed model-provider routing with content-free attempt evidence."""
from __future__ import annotations

import math
import time
import uuid
from collections.abc import Mapping

MODEL_KINDS = frozenset({"ANTHROPIC", "OPENAI"})
PROVIDER_ENDPOINTS = {
    "ANTHROPIC": "https://api.anthropic.com/v1/messages",
    "OPENAI": "https://api.openai.com/v1/chat/completions",
}
ERROR_KINDS = frozenset({"RATE_LIMIT", "SERVER", "TIMEOUT", "CONNECTION", "AUTH",
                         "INVALID_REQUEST", "INVALID_RESPONSE", "POLICY", "UNKNOWN"})
ACTIONS = frozenset({"BLOCK", "RETRY", "FAILOVER", "RETRY_THEN_FAILOVER"})


class ProviderCallError(RuntimeError):
    """Deliberately excludes SDK exception messages, bodies and credentials."""

    def __init__(self, kind: str, status_code: int | None = None, *, usage=None):
        self.kind = kind if kind in ERROR_KINDS else "UNKNOWN"
        self.status_code = status_code if type(status_code) is int else None
        self.usage = usage
        super().__init__("provider call failed: " + self.kind)


def classify_error(error: Exception) -> ProviderCallError:
    if isinstance(error, ProviderCallError):
        return error
    status = getattr(error, "status_code", None)
    if type(status) is int:
        kind = ("RATE_LIMIT" if status == 429 else "AUTH" if status in {401, 403}
                else "TIMEOUT" if status == 408 else "SERVER" if 500 <= status <= 599
                else "INVALID_REQUEST")
        return ProviderCallError(kind, status)
    # Both SDK generations have these names; no dependency import is necessary.
    if isinstance(error, TimeoutError) or type(error).__name__ in {"APITimeoutError", "ReadTimeout", "ConnectTimeout"}:
        return ProviderCallError("TIMEOUT")
    if isinstance(error, ConnectionError) or type(error).__name__ in {"APIConnectionError", "ConnectError"}:
        return ProviderCallError("CONNECTION")
    return ProviderCallError("UNKNOWN")


def provider_candidates(config: Mapping) -> tuple[dict, ...]:
    primary = {key: config[key] for key in ("kind", "model", "providerActorId", "credentialRef")}
    return (primary, *config.get("providerPolicy", {}).get("fallbacks", []))


def validate_provider_policy(config: Mapping) -> None:
    policy = config.get("providerPolicy", {})
    if not isinstance(policy, dict) or set(policy) - {"fallbacks", "maxAttempts", "retryDelaySeconds", "onError"}:
        raise ValueError("unsupported providerPolicy configuration")
    _validate_rules(policy)
    fallbacks = policy.get("fallbacks", [])
    if not isinstance(fallbacks, list) or len(fallbacks) > 3:
        raise ValueError("providerPolicy allows at most 3 explicit fallbacks")
    identities = set()
    for candidate in provider_candidates(config):
        required = {"kind", "model", "providerActorId", "credentialRef"}
        if (not isinstance(candidate, dict) or not required <= candidate.keys()
                or set(candidate) - required - {"policy"}):
            raise ValueError("provider candidate requires kind, model, providerActorId and credentialRef")
        if not isinstance(candidate["kind"], str) or candidate["kind"] not in MODEL_KINDS or any(
                not isinstance(candidate[key], str) or not candidate[key].strip() or len(candidate[key]) > 256
                for key in ("model", "providerActorId", "credentialRef")):
            raise ValueError("invalid provider candidate")
        identity = (candidate["providerActorId"], candidate["model"])
        if identity in identities:
            raise ValueError("provider candidates must be unique")
        identities.add(identity)
        override = candidate.get("policy", {})
        if not isinstance(override, dict) or set(override) - {"maxAttempts", "retryDelaySeconds", "onError"}:
            raise ValueError("invalid per-provider policy override")
        _validate_rules({**policy, **override})


def _validate_rules(policy):
    attempts = policy.get("maxAttempts", 1)
    if type(attempts) is not int or not 1 <= attempts <= 3:
        raise ValueError("providerPolicy maxAttempts must be between 1 and 3 per provider")
    delay = policy.get("retryDelaySeconds", 0)
    if type(delay) not in {float, int} or not 0 <= delay <= 2:
        raise ValueError("providerPolicy retryDelaySeconds must be between 0 and 2")
    rules = policy.get("onError", {})
    if not isinstance(rules, dict) or any(
            key not in ERROR_KINDS or not isinstance(action, str) or action not in ACTIONS
            or (key in {"POLICY", "INVALID_RESPONSE", "UNKNOWN"} and action != "BLOCK")
            for key, action in rules.items()):
        raise ValueError("invalid providerPolicy error rule; policy and unknown failures must block")


def token_usage(value) -> dict:
    """Absent billing information stays unknown, including a lost response."""
    if not isinstance(value, Mapping):
        return {"status": "UNKNOWN", "unit": "tokens", "inputCount": None, "outputCount": None}
    result = {}
    for target, names in (("inputCount", ("inputCount", "inputTokens", "input_tokens", "prompt_tokens")),
                          ("outputCount", ("outputCount", "outputTokens", "output_tokens", "completion_tokens")),
                          ("cacheReadCount", ("cache_read_input_tokens",)),
                          ("cacheCreationCount", ("cache_creation_input_tokens",))):
        number = next((value[name] for name in names if name in value), None)
        if type(number) is int and number >= 0:
            result[target] = number
    return {"status": "KNOWN" if {"inputCount", "outputCount"} <= result.keys() else "UNKNOWN",
            "unit": "tokens", "inputCount": None, "outputCount": None, **result}


def call_with_policy(config, invoke, record, *, deadline_epoch, sleep=time.sleep):
    """Retry only inference. The caller must authorize *every* invoke before transport.

    ``invoke(candidate, timeout)`` returns content, stopReason and usage. Neither this
    coordinator nor a provider adapter may execute model-selected tools.
    """
    validate_provider_policy(config)
    if type(deadline_epoch) not in {int, float} or not math.isfinite(deadline_epoch):
        raise ValueError("provider deadline must be a finite epoch timestamp")
    policy = config.get("providerPolicy", {})
    candidates = provider_candidates(config)
    for index, candidate in enumerate(candidates):
        candidate_policy = {**policy, **candidate.get("policy", {})}
        for attempt in range(1, candidate_policy.get("maxAttempts", 1) + 1):
            remaining = deadline_epoch - time.time()
            if remaining <= 0:
                raise ProviderCallError("TIMEOUT")
            started = time.monotonic()
            evidence = {"attemptId": str(uuid.uuid4()), "provider": candidate["kind"],
                        "providerActorId": candidate["providerActorId"], "model": candidate["model"],
                        "providerIndex": index, "attempt": attempt}
            try:
                response = invoke(candidate, min(20, remaining))
                if time.time() >= deadline_epoch:
                    raise ProviderCallError("TIMEOUT", usage=response.get("usage"))
            except Exception as error:
                failure = classify_error(error)
                action = candidate_policy.get("onError", {}).get(failure.kind, "BLOCK")
                can_retry = attempt < candidate_policy.get("maxAttempts", 1)
                can_failover = index + 1 < len(candidates)
                actual = ("RETRY" if action in {"RETRY", "RETRY_THEN_FAILOVER"} and can_retry
                          else "FAILOVER" if action in {"FAILOVER", "RETRY_THEN_FAILOVER"} and can_failover
                          else "BLOCK")
                delay = candidate_policy.get("retryDelaySeconds", 0)
                if time.time() + (delay if actual == "RETRY" else 0) >= deadline_epoch:
                    actual = "BLOCK"
                record({**evidence, "outcome": "ERROR", "errorKind": failure.kind,
                        "statusCode": failure.status_code, "action": actual,
                        "latencyMs": round((time.monotonic() - started) * 1000, 3),
                        "usage": token_usage(failure.usage)})
                if actual == "BLOCK":
                    raise failure from None
                if actual == "FAILOVER":
                    break
                if delay:
                    sleep(delay)
            else:
                record({**evidence, "outcome": "SUCCEEDED", "action": "COMPLETE", "errorKind": None,
                        "statusCode": None, "latencyMs": round((time.monotonic() - started) * 1000, 3),
                        "usage": token_usage(response.get("usage"))})
                return response
    raise ProviderCallError("UNKNOWN")
