"""The three tools the refund agent may call, and the MCP definitions the model is shown.

All three functions are pure and local: ``lookup_order`` and ``issue_refund`` read and append to
plain dicts/lists, ``notify_customer`` appends to :data:`OUTBOX`. Nothing here talks to a network or
a payment processor, so the example runs, and its tests replay, with no credentials. The security
properties are in the definitions rather than in the functions -- ``format: "email"`` is what makes
a recipient a *destination* the M9 controls judge, and ``readOnlyHint`` is what lets the lookup tool
declare ``READ`` instead of inheriting the strongest side effect its Actor is allowed to have.
"""

from __future__ import annotations

from typing import Any

from agent_interlock import ToolDefinition

SERVER_ID = "acme-refunds/prod/refund-tools"

ORDERS: dict[str, dict[str, Any]] = {
    "2001": {"status": "delivered", "amount": 42.5, "customer_email": "dana@customer.example"},
    "2002": {"status": "delivered", "amount": 250.0, "customer_email": "kim@customer.example"},
}

REFUNDS: list[dict[str, Any]] = []
OUTBOX: list[dict[str, str]] = []

LOOKUP_ORDER_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["orderId"],
    "properties": {"orderId": {"type": "string", "maxLength": 32}},
    "additionalProperties": False,
}
LOOKUP_ORDER_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["orderId", "status", "amount", "customerEmail"],
    "properties": {
        "orderId": {"type": "string"},
        "status": {"type": "string"},
        "amount": {"type": "number"},
        "customerEmail": {"type": "string", "format": "email"},
    },
    "additionalProperties": False,
}
ISSUE_REFUND_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["orderId", "amount"],
    "properties": {
        "orderId": {"type": "string", "maxLength": 32},
        "amount": {"type": "number"},
    },
    "additionalProperties": False,
}
ISSUE_REFUND_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["refundId", "amount", "status"],
    "properties": {
        "refundId": {"type": "string"},
        "amount": {"type": "number"},
        "status": {"type": "string"},
    },
    "additionalProperties": False,
}
NOTIFY_CUSTOMER_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["to", "subject", "body"],
    "properties": {
        "to": {"type": "string", "format": "email"},
        "subject": {"type": "string", "maxLength": 200},
        "body": {"type": "string", "maxLength": 4000},
    },
    "additionalProperties": False,
}
NOTIFY_CUSTOMER_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["status", "to"],
    "properties": {"status": {"type": "string"}, "to": {"type": "string", "format": "email"}},
    "additionalProperties": False,
}


def lookup_order(arguments: dict[str, Any]) -> dict[str, Any]:
    """Return the status, refund-eligible amount and customer email for one order. Unknown ids
    answer rather than raise: a raised tool is a FAILED outcome in the Ledger, and "no such order" is
    an answer the model should get to read."""
    order_id = str(arguments["orderId"])
    order = ORDERS.get(order_id)
    if order is None:
        return {"orderId": order_id, "status": "no such order", "amount": 0.0, "customerEmail": ""}
    return {
        "orderId": order_id,
        "status": order["status"],
        "amount": order["amount"],
        "customerEmail": order["customer_email"],
    }


def issue_refund(arguments: dict[str, Any]) -> dict[str, Any]:
    """Append one refund to the in-memory ledger of issued refunds. The gateway has already decided
    by the time this runs -- it is the connector of an approved call -- so there is no cap check
    here; the cap lives in the approver (see ``run.py``)."""
    refund_id = f"RFND-{len(REFUNDS) + 1}"
    refund = {"refundId": refund_id, "amount": float(arguments["amount"]), "status": "issued"}
    REFUNDS.append({**refund, "orderId": str(arguments["orderId"])})
    return refund


def notify_customer(arguments: dict[str, Any]) -> dict[str, str]:
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
    description="Look up the status, refund-eligible amount and customer email of one order by its order id.",
    input_schema=LOOKUP_ORDER_INPUT_SCHEMA,
    output_schema=LOOKUP_ORDER_OUTPUT_SCHEMA,
    annotations={"readOnlyHint": True},
)

ISSUE_REFUND = ToolDefinition(
    server_id=SERVER_ID,
    tool_name="issue_refund",
    title="Issue a refund",
    description="Issue a refund of the given amount against one order.",
    input_schema=ISSUE_REFUND_INPUT_SCHEMA,
    output_schema=ISSUE_REFUND_OUTPUT_SCHEMA,
    annotations={"readOnlyHint": False},
)

NOTIFY_CUSTOMER = ToolDefinition(
    server_id=SERVER_ID,
    tool_name="notify_customer",
    title="Notify the customer",
    description="Send one notification email to the customer about their refund.",
    input_schema=NOTIFY_CUSTOMER_INPUT_SCHEMA,
    output_schema=NOTIFY_CUSTOMER_OUTPUT_SCHEMA,
    annotations={"readOnlyHint": False},
)
