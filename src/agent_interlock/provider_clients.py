"""OpenAI wire adapter: one fixed pinned HTTP request, without SDK retries."""
from __future__ import annotations

import json

from .canonical import canonical_json
from .provider_policy import PROVIDER_ENDPOINTS, ProviderCallError


def openai_payload(candidate, *, messages, tools, system, max_tokens):
    """Return the same JSON object that both authorization and transport inspect."""
    converted = [{"role": "system", "content": system}]
    for message in messages:
        content = message["content"]
        if isinstance(content, str):
            converted.append({"role": message["role"], "content": content})
        elif message["role"] == "assistant":
            item = {"role": "assistant", "content": "\n".join(
                block["text"] for block in content if block["type"] == "text") or None}
            calls = [{"id": block["id"], "type": "function", "function": {
                "name": block["name"], "arguments": canonical_json(block["input"]).decode()}}
                for block in content if block["type"] == "tool_use"]
            if calls:
                item["tool_calls"] = calls
            converted.append(item)
        else:
            for block in content:
                if block["type"] != "tool_result":
                    raise ProviderCallError("INVALID_REQUEST")
                converted.append({"role": "tool", "tool_call_id": block["tool_use_id"],
                                  "content": block["content"]})
    return {"model": candidate["model"], "messages": converted,
        "max_completion_tokens": max_tokens, "parallel_tool_calls": False,
        "tools": [{"type": "function", "function": {"name": tool["name"],
                   "description": tool["description"], "parameters": tool["input_schema"]}} for tool in tools]}


def openai_request(candidate, *, request, messages, tools, system, max_tokens, key, timeout, payload=None):
    body = canonical_json(payload if payload is not None else openai_payload(candidate, messages=messages,
        tools=tools, system=system, max_tokens=max_tokens))
    if len(body) > 1_048_576:
        raise ProviderCallError("INVALID_REQUEST")
    status, _, content = request(PROVIDER_ENDPOINTS["OPENAI"], "POST", body,
        {"Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json",
         "Accept-Encoding": "identity"}, timeout=timeout)
    if not 200 <= status < 300:
        raise ProviderCallError("RATE_LIMIT" if status == 429 else "AUTH" if status in {401, 403}
            else "TIMEOUT" if status == 408 else "SERVER" if status >= 500 else "INVALID_REQUEST", status)
    response = None
    try:
        response = json.loads(content)
        choices = response["choices"]
        if len(choices) != 1:
            raise ValueError("expected one choice")
        choice = choices[0]
        message = choice["message"]
        if not isinstance(message, dict) or message.get("refusal") is not None:
            raise ValueError("provider refused the task")
        blocks = []
        if message.get("content") is not None:
            if not isinstance(message["content"], str):
                raise ValueError("invalid text")
            blocks.append({"type": "text", "text": message["content"]})
        for call in message.get("tool_calls", []):
            arguments = json.loads(call["function"]["arguments"])
            if (call["type"] != "function" or not isinstance(arguments, dict)
                    or not isinstance(call["id"], str) or not isinstance(call["function"]["name"], str)):
                raise ValueError("invalid call")
            blocks.append({"type": "tool_use", "id": call["id"], "name": call["function"]["name"],
                           "input": arguments})
        calls = [block for block in blocks if block["type"] == "tool_use"]
        finish = choice["finish_reason"]
        if (finish not in {"stop", "tool_calls"} or (finish == "tool_calls") != bool(calls)
                or (finish == "stop" and not any(block.get("text", "").strip() for block in blocks))):
            raise ValueError("provider did not complete a text or tool turn")
        stop = {"stop": "end_turn", "tool_calls": "tool_use"}[finish]
        return {"content": blocks, "stopReason": stop, "usage": response.get("usage")}
    except (ValueError, TypeError, KeyError, IndexError):
        raise ProviderCallError("INVALID_RESPONSE", status,
                                usage=response.get("usage") if isinstance(response, dict) else None) from None
