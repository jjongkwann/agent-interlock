"""Trust boundary -> A2A broker -> workflow orchestration vertical slice."""

from __future__ import annotations

import json
from pathlib import Path

from agent_interlock import (
    A2AAgentCard,
    A2AAgentSkill,
    A2AArtifact,
    A2ABroker,
    A2AHandlerResult,
    A2AMessage,
    A2AMessageRole,
    A2AOrchestrationAdapter,
    A2APart,
    A2APrincipal,
    A2ATaskState,
    ArchitectureCompiler,
    ArchitectureGraph,
    CallableTaskAdapter,
    InMemoryLedger,
    OrchestrationEngine,
    TaskExecutionResult,
    TaskTransport,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"


manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
architecture = ArchitectureCompiler().compile(ArchitectureGraph.from_dict(manifest))
ledger = InMemoryLedger()
broker = A2ABroker(architecture, ledger=ledger)


def research_handler(task, message, context):
    """A real host would delegate this call to its agent framework."""

    request = message.parts[0].data or {}
    question = request.get("input", {}).get("question", "")
    return A2AHandlerResult(
        state=A2ATaskState.COMPLETED,
        message=A2AMessage(
            role=A2AMessageRole.AGENT,
            parts=(A2APart.text_part("Tenant-scoped research completed."),),
        ),
        artifacts=(
            A2AArtifact(
                artifact_id=f"artifact:{task.id}",
                name="Grounded support research",
                parts=(
                    A2APart.data_part(
                        {
                            "question": question,
                            "answer": "Use the approved reset workflow.",
                            "grounded": True,
                        }
                    ),
                ),
            ),
        ),
    )


broker.register_agent(
    "agent.research",
    A2AAgentCard(
        actor_id="agent.research",
        name="Research agent",
        description="Finds tenant-scoped support knowledge.",
        url="https://agents.example/a2a/research",
        version="1.0.0",
        skills=(
            A2AAgentSkill(
                id="KNOWLEDGE_SEARCH",
                name="Knowledge search",
                description="Searches approved tenant knowledge.",
            ),
        ),
    ),
    research_handler,
)


def a2a_principal(task, tenant_id, run_id):
    target = architecture.actors[task.target_actor_id]
    return A2APrincipal.for_edge(
        tenant_id=tenant_id,
        subject=run_id,
        source_actor_id=task.source_actor_id,
        target_actor_id=task.target_actor_id,
        target_identity=target.identity,
        delegation_depth=1,
    )


def demo_mcp_adapter(value):
    """The orchestration seam where the existing MCP gateway adapter is wired."""

    research = value.dependency_outputs["task.research"]
    return TaskExecutionResult(
        output={
            "delivery": "simulated",
            "researchTask": research["a2aTaskId"],
            "receiptId": f"receipt-demo-{research['a2aTaskId']}",
        },
        metadata={"accepted": True, "transport": "MCP-demo"},
    )


engine = OrchestrationEngine(
    architecture,
    adapters={
        TaskTransport.A2A: A2AOrchestrationAdapter(broker, a2a_principal),
        TaskTransport.MCP: CallableTaskAdapter(demo_mcp_adapter),
    },
    approval_provider=lambda tenant_id, run_id, task, context: True,
    ledger=ledger,
)
run = engine.start(
    tenant_id="tenant-a",
    run_id="support-run-001",
    trace_id="trace-a2a-orchestration",
    workflow_input={"question": "How do I reset the device?"},
)

assert run.state.value == "COMPLETED"
assert run.tasks["task.research"].external_task_id is not None

print(
    json.dumps(
        {
            "run": run.to_dict(),
            "boundary": architecture.boundary_for(
                architecture.edge_for("agent.support", "agent.research", "REL-06")
            ).id,
            "ledgerEventTypes": [event.event_type for event in ledger.all()],
        },
        indent=2,
        ensure_ascii=False,
    )
)
