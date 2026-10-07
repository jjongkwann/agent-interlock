"""Bind real Python tools to a reviewed deployment, without reloading a local manifest."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from .adapters.anthropic_tools import Approver, ToolBinding, bind_architecture, guard_tools
from .architecture import ArchitectureCompiler, CompiledArchitecture
from .canonical import canonical_digest
from .gateway import MCPToolGateway
from .ledger import Ledger
from .models import DataSource, Environment
from .studio_deploy import GitBundleStore, deployed_architecture


def load_promoted_architecture(store: GitBundleStore) -> CompiledArchitecture:
    active = store.active()
    if not active or active.get("mode") != "ENFORCE":
        raise ValueError("managed runtime requires a promoted ENFORCE bundle")
    bundle = store.bundle(active["bundleDigest"])
    return replace(
        ArchitectureCompiler().compile(deployed_architecture(bundle.body, "ENFORCE")),
        bundle_digest=bundle.bundle_digest,
    )


def build_managed_tools(
    compiled: CompiledArchitecture, *, bindings: Sequence[ToolBinding], tenant_id: str,
    source_actor_id: str, ledger: Ledger, approver: str, approve: Approver | None = None,
    trace_id: str | None = None,
):
    """Build from the exact compiled bundle supplied by Run Control or load_promoted_architecture.

    Every graph actor and policy is registered. Only the bound callable invocations execute here;
    authored controls on other edges are not evidence of installed enforcement hooks.
    """
    if not compiled.bundle_digest:
        raise ValueError("managed runtime requires a bundle digest")
    for binding in bindings:
        actor = compiled.actors.get(binding.actor_id)
        if actor is None or actor.definition_digest != canonical_digest(binding.definition.canonical_value()):
            raise ValueError(f"reviewed definition digest does not match {binding.actor_id}")
        if binding.classify is None or binding.estimate_export is None or binding.result_provenance is None:
            raise ValueError(f"managed tool {binding.actor_id} requires classification, export and provenance hooks")
    gateway = MCPToolGateway(ledger=ledger, bundle_digest=compiled.bundle_digest)
    for actor in compiled.actors.values():
        gateway.register_actor(actor)
    for edge in compiled.graph.edges:
        gateway.connect(edge.source, edge.target, compiled.links[edge.id])
    bind_architecture(
        gateway, compiled, tool_bindings={b.definition.tool_name: b.actor_id for b in bindings}, approver=approver,
    )
    return gateway, guard_tools(
        gateway, tenant_id=tenant_id, source_actor_id=source_actor_id, bindings=bindings,
        approver=approver, approve=approve, trace_id=trace_id,
        environment=Environment.PROD, data_source=DataSource.PRODUCTION,
    )
