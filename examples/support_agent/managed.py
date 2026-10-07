"""Support workflow adapters and a reviewable, pinned manifest for the managed host."""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent_interlock.architecture import ArchitectureGraph, CompiledArchitecture, TaskTransport
from agent_interlock.ledger import Ledger
from agent_interlock.managed_runtime import build_managed_tools, load_promoted_architecture
from agent_interlock.orchestration import CallableTaskAdapter, TaskExecutionInput, TaskExecutionResult, WorkflowRunStore
from agent_interlock.studio_deploy import GitBundleStore

from .build import APPROVER, BINDINGS, MANIFEST, SOURCE_ACTOR_ID, TENANT_ID, _pin_definitions


def build(*, store: GitBundleStore, ledger: Ledger, approve=None):
    """The tools returned here can be passed directly to Anthropic's Tool Runner."""
    return build_managed_tools(
        load_promoted_architecture(store), bindings=BINDINGS, tenant_id=TENANT_ID,
        source_actor_id=SOURCE_ACTOR_ID, ledger=ledger, approver=APPROVER, approve=approve,
    )


def adapter_provider(ledger: Ledger, run_store: WorkflowRunStore):
    def provide(compiled: CompiledArchitecture):
        if compiled.graph.orchestration is None:
            raise ValueError("support host requires an orchestration definition")
        bindings = {binding.actor_id: binding for binding in BINDINGS}
        for task in compiled.graph.orchestration.tasks:
            binding = bindings.get(task.target_actor_id)
            if (binding is None or task.source_actor_id != SOURCE_ACTOR_ID or task.purpose != binding.purpose
                    or task.transport != TaskTransport.LOCAL):
                raise ValueError(f"support host has no adapter for task {task.id}")

        def execute(value: TaskExecutionInput) -> TaskExecutionResult:
            binding = bindings[value.task.target_actor_id]
            arguments = value.workflow_input.get(binding.definition.tool_name)
            if not isinstance(arguments, Mapping):
                raise ValueError(f"input.{binding.definition.tool_name} must be an argument object")
            run = run_store.get(tenant_id=value.tenant_id, run_id=value.run_id)
            approved_by = run.approvals.get(value.task.id) if value.task.approval_required else None
            _, tools = build_managed_tools(
                compiled, bindings=[binding], tenant_id=value.tenant_id,
                source_actor_id=value.task.source_actor_id, ledger=ledger, approver=APPROVER,
                approve=(lambda _args, _decision: approved_by) if approved_by else None,
                trace_id=value.trace_id,
            )
            output = json.loads(tools[0].call(dict(arguments)))
            if not isinstance(output, Mapping):
                raise ValueError("support tool must return an object")
            return TaskExecutionResult(output=output, metadata={"bundleDigest": compiled.bundle_digest})

        return {TaskTransport.LOCAL: CallableTaskAdapter(execute)}
    return provide


def manifest() -> dict[str, Any]:
    graph = _pin_definitions(ArchitectureGraph.from_dict(json.loads(MANIFEST.read_text())), BINDINGS)
    value = graph.to_manifest()
    value["spec"]["orchestration"] = {
        "coordinatorActorId": SOURCE_ACTOR_ID,
        "pattern": "STATE_GRAPH",
        "tasks": [
            {"id": "lookup-order", "label": "Look up the order", "sourceActorId": SOURCE_ACTOR_ID,
             "targetActorId": "tool.lookup-order", "transport": "LOCAL", "purpose": "SUPPORT_LOOKUP",
             "acceptanceCriteria": ["required:order_id"]},
            {"id": "send-email", "label": "Send the approved reply", "sourceActorId": SOURCE_ACTOR_ID,
             "targetActorId": "tool.send-email", "transport": "LOCAL", "purpose": "SUPPORT_REPLY",
             "dependsOn": ["lookup-order"], "approvalRequired": True,
             "acceptanceCriteria": ["equals:status=sent"]},
        ],
    }
    return value


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Write the pinned support manifest for review and compilation")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(manifest(), indent=2) + "\n", encoding="utf-8")
