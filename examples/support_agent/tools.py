"""The two tools the support agent may call, and the MCP definitions the model is shown.

Both functions are pure and local: ``lookup_order`` reads a dict, ``send_email`` appends to
:data:`OUTBOX`. Nothing here talks to a network, so the example runs, and its tests replay, with no
credentials and no mail server. The security properties are in the definitions rather than in the
functions -- ``format: "email"`` is what makes a recipient a *destination* the M9 controls judge,
and ``readOnlyHint`` is what lets the lookup tool declare ``READ`` instead of inheriting the
strongest side effect its Actor is allowed to have.
"""

from __future__ import annotations

from typing import Any

from agent_interlock import ToolDefinition

SERVER_ID = "acme-support/prod/support-tools"

ORDERS: dict[str, dict[str, str]] = {
    "1001": {"status": "shipped, arriving Tuesday", "customer_email": "dana@customer.example"},
    "1002": {"status": "awaiting payment", "customer_email": "kim@customer.example"},
}

OUTBOX: list[dict[str, str]] = []

LOOKUP_ORDER_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["order_id"],
    "properties": {"order_id": {"type": "string", "maxLength": 32}},
    "additionalProperties": False,
}
LOOKUP_ORDER_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["order_id", "status", "customer_email"],
    "properties": {
        "order_id": {"type": "string"},
        "status": {"type": "string"},
        "customer_email": {"type": "string", "format": "email"},
    },
    "additionalProperties": False,
}
SEND_EMAIL_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["to", "subject", "body"],
    "properties": {
        "to": {"type": "string", "format": "email"},
        "subject": {"type": "string", "maxLength": 200},
        "body": {"type": "string", "maxLength": 4000},
    },
    "additionalProperties": False,
}
SEND_EMAIL_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["status", "to"],
    "properties": {"status": {"type": "string"}, "to": {"type": "string", "format": "email"}},
    "additionalProperties": False,
}


def lookup_order(arguments: dict[str, Any]) -> dict[str, str]:
    """Return the status of one order. Unknown ids answer rather than raise: a raised tool is a
    FAILED outcome in the Ledger, and "no such order" is an answer the model should get to read."""
    order_id = str(arguments["order_id"])
    order = ORDERS.get(order_id)
    if order is None:
        return {"order_id": order_id, "status": "no such order", "customer_email": ""}
    return {"order_id": order_id, **order}


def send_email(arguments: dict[str, Any]) -> dict[str, str]:
    """Append one message to the in-memory outbox. The gateway has already decided by the time this
    runs -- it is the connector of an approved call -- so there is no recipient check here."""
    message = {
        "to": str(arguments["to"]),
        "subject": str(arguments["subject"]),
        "body": str(arguments["body"]),
    }
    OUTBOX.append(message)
    return {"status": "sent", "to": message["to"]}


LOOKUP_ORDER = ToolDefinition(
    server_id=SERVER_ID,
    tool_name="lookup_order",
    title="Look up an order",
    description="Look up the status of one customer order by its order id.",
    input_schema=LOOKUP_ORDER_INPUT_SCHEMA,
    output_schema=LOOKUP_ORDER_OUTPUT_SCHEMA,
    annotations={"readOnlyHint": True},
)

SEND_EMAIL = ToolDefinition(
    server_id=SERVER_ID,
    tool_name="send_email",
    title="Send a customer email",
    description="Send one reply email to the customer who owns the order.",
    input_schema=SEND_EMAIL_INPUT_SCHEMA,
    output_schema=SEND_EMAIL_OUTPUT_SCHEMA,
    annotations={"readOnlyHint": False},
)


def classify_support_data(_arguments: dict[str, Any]) -> frozenset[str]:
    """This example's order identifiers and customer replies are customer data (D3)."""
    return frozenset({"D3"})


def estimate_support_export(arguments: dict[str, Any]) -> tuple[int, int]:
    from agent_interlock.canonical import canonical_json

    return 1, len(canonical_json(arguments))


def support_result_provenance(_result: Any) -> dict[str, Any]:
    return {"dataClasses": ["D3"], "source": "support-example-local-data", "simulatedBusinessData": True}
