"""Reviewed read → approve change → verify workflow for the real product API."""
from __future__ import annotations

import json
from dataclasses import replace

from agent_interlock import ToolBinding, ToolDefinition
from agent_interlock.architecture import (
    ArchitectureCompiler,
    ArchitectureEdge,
    ArchitectureGraph,
    ArchitectureNode,
    AssuranceLevel,
    ControlTiming,
    EnforcementPoint,
    OrchestrationDefinition,
    OrchestrationPattern,
    OrchestrationTask,
    SecurityControl,
    SecurityObjective,
    TaskTransport,
)
from agent_interlock.canonical import canonical_digest, canonical_json
from agent_interlock.effects import EffectJournal, EffectResolution, EffectStatus
from agent_interlock.managed_runtime import build_managed_tools
from agent_interlock.models import ActorSpec, ActorType, LinkPolicy, SideEffect
from agent_interlock.orchestration import CallableTaskAdapter, OrchestrationError, TaskExecutionResult

from .client import fingerprint

TENANT = "todayplanner-disposable"
SOURCE = "agent.planner"
READER = "tool.read-schedule"
WRITER = "tool.update-schedule"
TASK_ID_SCHEMA = {"type": "string", "pattern": "^[A-Za-z0-9-]{1,128}$"}
READ_SCHEMA = {"type": "object", "required": ["taskId"], "properties": {"taskId": TASK_ID_SCHEMA},
               "additionalProperties": False}
WRITE_SCHEMA = {"type": "object", "required": ["taskId", "expectedRevision", "patch"], "properties": {
    "taskId": TASK_ID_SCHEMA, "expectedRevision": {"type": "integer"},
    "patch": {"type": "object", "required": ["startMinute"], "properties": {
        "startMinute": {"type": "integer"}}, "additionalProperties": False},
}, "additionalProperties": False}
OUTPUT_SCHEMA = {"type": "object", "required": ["revision", "task"], "properties": {
    "revision": {"type": "integer"}, "task": {"type": "object"}}, "additionalProperties": False}
READ = ToolDefinition(server_id="todayplanner-local", tool_name="read_schedule",
                      title="Read the selected schedule", description="Read one selected account-owned schedule.",
                      input_schema=READ_SCHEMA, output_schema=OUTPUT_SCHEMA, annotations={"readOnlyHint": True})
WRITE = ToolDefinition(server_id="todayplanner-local", tool_name="update_schedule",
                       title="Change approved schedule time", description="Change only the approved start minute.",
                       input_schema=WRITE_SCHEMA, output_schema=OUTPUT_SCHEMA, annotations={"readOnlyHint": False})


def architecture(start_minute):
    source = ArchitectureNode(ActorSpec(SOURCE, ActorType.AGENT, "fixture", "fixture-planner",
                                        data_access=frozenset({"D3"})))
    nodes, edges = [source], []
    for actor_id, tool, purpose, write in [(READER, READ, "READ_SCHEDULE", False),
                                          (WRITER, WRITE, "UPDATE_SCHEDULE", True)]:
        nodes.append(ArchitectureNode(ActorSpec(
            actor_id, ActorType.TOOL, "fixture", actor_id, data_access=frozenset({"D3"}),
            side_effects=frozenset({SideEffect.EXTERNAL_WRITE if write else SideEffect.READ}),
            input_schema=tool.input_schema, output_schema=tool.output_schema,
            definition_digest=canonical_digest(tool.canonical_value()),
        )))
        edges.append(ArchitectureEdge(
            "invoke-" + actor_id, "REL-05", SOURCE, actor_id, "INVOKES",
            LinkPolicy(allowed_purposes=frozenset({purpose}), allowed_data_classes=frozenset({"D3"}),
                       require_explicit_destination=False, external_write_requires_approval=write,
                       max_export_records=1, max_export_bytes=8192),
            controls=(SecurityControl("guard-" + actor_id, SecurityObjective.PREVENT,
                                      ControlTiming.PRE_EXECUTION, EnforcementPoint.MCP_GATEWAY,
                                      AssuranceLevel.ENFORCED),),
        ))
    tasks = (
        OrchestrationTask("read", "Read current schedule", SOURCE, READER, TaskTransport.LOCAL, "READ_SCHEDULE",
                          acceptance_criteria=("required:task.id",)),
        OrchestrationTask("change", "Approve and change schedule", SOURCE, WRITER, TaskTransport.LOCAL,
                          "UPDATE_SCHEDULE", depends_on=("read",), approval_required=True,
                          acceptance_criteria=(f"equals:task.startMinute={start_minute}",)),
        OrchestrationTask("verify", "Read back saved schedule", SOURCE, READER, TaskTransport.LOCAL, "READ_SCHEDULE",
                          depends_on=("change",), acceptance_criteria=(f"equals:task.startMinute={start_minute}",)),
    )
    graph = ArchitectureGraph("todayplanner-recovery", "1", tuple(nodes), tuple(edges),
                              orchestration=OrchestrationDefinition(coordinator_actor_id=SOURCE,
                                  pattern=OrchestrationPattern.STATE_GRAPH, tasks=tasks))
    return replace(ArchitectureCompiler().compile(graph), bundle_digest=canonical_digest(graph.to_manifest()))


def bindings(client, *, send=None, write_purpose="UPDATE_SCHEDULE"):
    def read(arguments):
        state = client.state()
        selected = next(task for task in state["tasks"] if task["id"] == arguments["taskId"])
        return {"revision": state["revision"], "task": selected}

    def binding(definition, function, actor_id, purpose):
        return ToolBinding(definition, function, actor_id, purpose,
                           classify=lambda _: frozenset({"D3"}),
                           estimate_export=lambda value: (1, len(canonical_json(value))),
                           result_provenance=lambda _: {"dataClasses": ["D3"], "source": "todayPlanner API",
                                                       "syntheticUserData": True})

    return (binding(READ, read, READER, "READ_SCHEDULE"), binding(WRITE, send, WRITER, write_purpose))


def adapters(compiled, client, store, ledger, *, fault=None):
    journal = EffectJournal(store, ledger)
    pending_fault = fault

    def execute(value):
        nonlocal pending_fault
        arguments = dict(value.workflow_input["change"])
        write = value.task.id == "change"
        if not write:
            arguments = {"taskId": arguments["taskId"]}
        transport = {}

        def send(call_arguments):
            nonlocal pending_fault
            if transport["confirmed"] is not None:
                return transport["confirmed"]
            injected_fault, pending_fault = pending_fault, None
            return client.update(call_arguments, transport["key"], fault=injected_fault)

        binding = bindings(client, send=send)[int(write)]
        run = store.get(tenant_id=value.tenant_id, run_id=value.run_id)
        approver = run.approvals.get(value.task.id)
        _, tools = build_managed_tools(compiled, bindings=[binding], tenant_id=value.tenant_id,
            source_actor_id=SOURCE, ledger=ledger, approver="fixture-reviewed-policy",
            approve=(lambda args, _: approver if dict(args) == arguments else None), trace_id=value.trace_id)
        tool = tools[0]
        decision = tool._decide(arguments)
        if not decision.permits_execution:
            raise OrchestrationError("PLANNER-POLICY-DENIED", ", ".join(decision.reason_codes))

        def dispatch(key, confirmed):
            transport.update(key=key, confirmed=confirmed)
            return json.loads(tool._execute_decision(arguments, decision))

        output = journal.execute(value, {
            "sourceActorId": SOURCE, "targetActorId": WRITER, "toolName": WRITE.tool_name,
            "definitionDigest": compiled.actors[WRITER].definition_digest,
            "arguments": arguments, "requestFingerprint": fingerprint(arguments),
        }, dispatch) if write else json.loads(tool._execute_decision(arguments, decision))
        return TaskExecutionResult(output=output)

    return {TaskTransport.LOCAL: CallableTaskAdapter(execute)}


def resolver(client, *, seal=False):
    def resolve(_run, _task_id, checkpoint):
        expected = checkpoint["invocation"]["requestFingerprint"]
        receipt = client.receipt(checkpoint["idempotencyKey"], expected, seal=seal)
        if receipt.get("operationId") != checkpoint["idempotencyKey"] or receipt.get("fingerprint") != expected:
            raise ValueError("product receipt does not match the durable request")
        status = EffectStatus(receipt["status"].upper())
        return EffectResolution(status, checkpoint["idempotencyKey"], checkpoint["invocationDigest"],
                                "todayPlanner atomic operation receipt: " + receipt["operationId"],
                                result=receipt.get("result"), fenced=status == EffectStatus.NOT_EXECUTED)
    return resolve
