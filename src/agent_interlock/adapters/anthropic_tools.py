"""Anthropic Tool Runner adapter: a guarded tool the SDK's agentic loop can run.

``client.beta.messages.tool_runner`` yields each assistant turn and then calls ``tool.call(input)``
for every ``tool_use`` block. That call site is the last point before a model-chosen argument map
reaches a real side effect, so it is where the gateway belongs. A :class:`GuardedTool` implements
the SDK's runnable-tool contract -- ``name``, ``to_dict()``, ``call(input)`` -- around one
:class:`~agent_interlock.models.ToolDefinition` and one callable, and runs the two-phase gateway
path in between: ``evaluate_invocation`` decides, ``execute_approved_call`` runs the callable as
the connector and returns what ``inspect_result`` produced.

The ``anthropic`` package is an optional extra and nothing here imports it at module scope. Two
places need it and both import lazily, with a fallback: the exception class the runner turns into
an ``is_error`` tool result, and the ABC registration that makes the runner recognise a guarded
tool as runnable. Everything in this module works, and is tested, with ``anthropic`` absent.

**A block never raises into the loop.** The model is told, in the tool result, that Interlock
refused the call and which reason codes fired, so it can choose a different action instead of the
run dying. A *definition* that fails admission is the opposite case: see :func:`guard_tools`.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from ..architecture import ArchitectureCompiler, ArchitectureGraph, CompiledArchitecture
from ..canonical import canonical_json
from ..gateway import InvocationBlocked, MCPToolGateway
from ..intent import derive_intent, side_effect_rank
from ..mcp_transport import bind_gateway_actors
from ..models import (
    ActorSpec,
    ActorType,
    CredentialClaims,
    DataSource,
    DefinitionState,
    Environment,
    InvocationIntent,
    PolicyDecisionRecord,
    SideEffect,
    ToolDefinition,
)
from ..registry import ToolRevision
from ..security import canonical_destination

Classifier = Callable[[Mapping[str, Any]], frozenset[str]]
# Called with the exact arguments the model chose and the decision that held them for approval.
# Returns the approver's identity to grant an approval bound to those arguments, or None to refuse.
Approver = Callable[[Mapping[str, Any], PolicyDecisionRecord], str | None]
APPROVAL_REQUIRED = "INTERLOCK-APPROVAL-REQUIRED"


class GuardedToolError(Exception):
    """Stand-in for ``anthropic.lib.tools.ToolError`` when the SDK is not installed.

    Same shape -- a ``content`` attribute the runner would read -- so a test, or a project running
    its tools through something other than the Anthropic SDK, sees one exception contract either
    way. :class:`GuardedTool` raises the SDK's class when it can import it and this one otherwise.
    """

    def __init__(self, content: Any) -> None:
        super().__init__(content if isinstance(content, str) else "Tool error")
        self.content = content


@dataclass(frozen=True, slots=True)
class ToolBinding:
    """One tool the model may call: what it is, what runs it, and who it is in the architecture.

    ``definition`` is the MCP-shaped definition the gateway admits and digests, and the same one
    the model sees -- ``to_dict()`` is derived from it, so the description and schema that were
    reviewed are the description and schema in the request. ``function`` is the real callable, run
    only as the gateway's connector. ``actor_id`` names the TOOL actor in the compiled architecture
    that carries this tool's allowlists and digest pin. ``purpose`` is declared on every invocation
    and has to be in the link policy's ``allowedPurposes``.
    """

    definition: ToolDefinition
    function: Callable[[Mapping[str, Any]], Any]
    actor_id: str
    purpose: str

    def __post_init__(self) -> None:
        if not self.actor_id or not self.purpose:
            raise ValueError("ToolBinding actor_id and purpose are required")


_REGISTERED_WITH_SDK = False


def _claim_the_runnable_tool_contract() -> None:
    """Tell the SDK's ABCs that a guarded tool is one of theirs.

    ``client.beta.messages.tool_runner`` sorts its ``tools`` argument with a real ``isinstance``
    against ``BetaBuiltinFunctionTool`` / ``BetaAsyncBuiltinFunctionTool``: anything else is
    forwarded to the API as a raw tool param and never dispatched locally, so structural
    conformance alone would leave the guard silently unused. Both are ABCs, so registering as a
    virtual subclass claims the contract without inheriting from the SDK or importing it at module
    scope. Called from the tool constructor, once per process, and a no-op when the SDK is absent.
    """
    global _REGISTERED_WITH_SDK
    if _REGISTERED_WITH_SDK:
        return
    try:
        from anthropic.lib.tools import BetaAsyncBuiltinFunctionTool, BetaBuiltinFunctionTool
    except Exception:  # noqa: BLE001 -- see _tool_error_class
        return
    BetaBuiltinFunctionTool.register(GuardedTool)
    BetaAsyncBuiltinFunctionTool.register(GuardedAsyncTool)
    _REGISTERED_WITH_SDK = True


def _tool_error_class() -> type[Exception]:
    """The exception the tool runner maps to an ``is_error`` tool result.

    Imported here rather than at module scope so the package imports with ``anthropic`` absent.
    """
    try:
        from anthropic.lib.tools import ToolError
    except Exception:  # noqa: BLE001 -- absent, shadowed by a test, or a broken install: all local
        return GuardedToolError
    return ToolError


def _arguments(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"tool input must be a JSON object, got {type(value).__name__}")
    return dict(value)


def _serialise(value: Any) -> str:
    """The clean result as one text block. A string goes back as itself; anything else goes back as
    canonical JSON, the same encoding the ledger hashed it under."""
    if isinstance(value, str):
        return value
    return canonical_json(value).decode("utf-8")


class _GuardedToolBase:
    """State and judgment shared by the sync and async guarded tools.

    Subclasses differ only in how they drive the callable; every decision below this line -- what
    the model is shown, what is declared to the gateway, how a block is reported -- is here so the
    two cannot drift apart.
    """

    def __init__(
        self,
        gateway: MCPToolGateway,
        binding: ToolBinding,
        revision: ToolRevision,
        *,
        tenant_id: str,
        source_actor_id: str,
        environment: Environment = Environment.DEV,
        data_source: DataSource = DataSource.PRODUCTION,
        classify: Classifier | None = None,
        credential: CredentialClaims | None = None,
        trace_id: str | None = None,
        approve: Approver | None = None,
    ) -> None:
        self._gateway = gateway
        self._binding = binding
        self._revision = revision
        self._tenant_id = tenant_id
        self._source_actor_id = source_actor_id
        self._environment = environment
        self._data_source = data_source
        self._classify = classify
        self._credential = credential
        self._trace_id = trace_id
        self._approve = approve
        _claim_the_runnable_tool_contract()

    @property
    def name(self) -> str:
        return self._binding.definition.tool_name

    @property
    def revision(self) -> ToolRevision:
        """The pinned revision the gateway judges this tool against."""
        return self._revision

    def to_dict(self) -> dict[str, Any]:
        """The tool as the API takes it.

        ``BetaToolParam`` accepts ``name``, ``description`` and ``input_schema`` and nothing that
        would carry an output schema, so the output schema stays where it is enforced -- on the
        result, in ``inspect_result`` -- rather than being advertised to the model.
        """
        definition = self._binding.definition
        return {
            "name": definition.tool_name,
            "description": definition.description,
            "input_schema": dict(definition.input_schema),
        }

    def _declared_intent(self, arguments: Mapping[str, Any]) -> InvocationIntent:
        """Declare what the arguments say, not what the caller hopes.

        ``INTERLOCK-INTENT-ARGUMENT-MISMATCH`` judges a declaration against a derivation from the
        tool's own schema and annotations, so an adapter that declared anything else would be
        declaring its way past the M9 controls. Destinations are the derived ones verbatim. The
        side effect is the derived one when the annotations assert one; otherwise the strongest
        effect the tool actor is allowed to have, which is the fail-closed reading of "this tool
        can do these things and did not say which one this call is".

        ``estimated_record_count`` is left at 0: the model's tool call carries no volume estimate,
        and 0 is how the volume controls spell "nothing to compare the cap against". Inventing a
        count would report a control as having examined an estimate nobody made.
        """
        definition = self._binding.definition
        derived = derive_intent(arguments, definition.input_schema, definition.annotations)
        side_effect = derived.side_effect
        if side_effect is None:
            side_effect = _strongest_declared(self._gateway.actor(self._binding.actor_id))
        data_classes = self._classify(arguments) if self._classify is not None else None
        # An approval is bound to the exact arguments and destinations, never to a tool or a
        # session, so the lookup is by what this call carries. The model never sees an approval id.
        approval = self._gateway.find_approval(
            tenant_id=self._tenant_id, arguments=arguments, destinations=derived.destinations
        )
        intent = InvocationIntent(
            purpose=self._binding.purpose,
            destinations=derived.destinations,
            estimated_side_effect=side_effect,
            estimated_record_count=0,
            approval_id=approval.approval_id if approval is not None else None,
        )
        return intent if data_classes is None else replace(intent, data_classes=data_classes)

    def _decide(self, arguments: Mapping[str, Any]) -> PolicyDecisionRecord:
        """Evaluate, and give an operator one chance to approve a call held only for approval.

        The first evaluation stays in the ledger as the HOLD it was: a CONTROL_EVALUATED with
        INTERLOCK-APPROVAL-REQUIRED and no action, which is what "waited for a human" looks like
        in the statistics. When the approver grants, the approval is bound to these exact
        arguments and destinations and the call is evaluated again; every other control still has
        to clear on that second pass, so an approval cannot launder a denied destination.
        """
        decision = self._evaluate(arguments)
        if decision.permits_execution or self._approve is None or APPROVAL_REQUIRED not in decision.reason_codes:
            return decision
        approver = self._approve(arguments, decision)
        if approver is None:
            return decision
        destinations = self._declared_intent(arguments).destinations
        self._gateway.grant_approval(
            tenant_id=self._tenant_id,
            arguments=arguments,
            canonical_destinations=tuple(canonical_destination(item) for item in destinations),
            approver=approver,
        )
        return self._evaluate(arguments)

    def _evaluate(self, arguments: Mapping[str, Any]) -> PolicyDecisionRecord:
        return self._gateway.evaluate_invocation(
            tenant_id=self._tenant_id,
            source_actor_id=self._source_actor_id,
            revision_id=self._revision.revision_id,
            intent=self._declared_intent(arguments),
            arguments=arguments,
            credential=self._credential,
            trace_id=self._trace_id,
            environment=self._environment,
            data_source=self._data_source,
        )

    def _blocked(self, decision: PolicyDecisionRecord) -> Exception:
        reasons = ", ".join(decision.reason_codes) or "no reason code"
        return _tool_error_class()(f"Blocked by Agent Interlock: {decision.decision.value} — {reasons}")


class GuardedTool(_GuardedToolBase):
    """A synchronous runnable tool for ``client.beta.messages.tool_runner``."""

    def call(self, input: object) -> str:
        arguments = _arguments(input)
        decision = self._decide(arguments)
        try:
            result = self._gateway.execute_approved_call(
                decision.decision_id,
                arguments,
                self._binding.function,
                idempotency_key=str(uuid.uuid4()),
            )
        except InvocationBlocked as blocked:
            raise self._blocked(blocked.decision) from blocked
        return _serialise(result.value)


class GuardedAsyncTool(_GuardedToolBase):
    """The async twin, for ``BetaAsyncToolRunner`` and an ``async def`` tool function.

    The gateway is synchronous end to end, so its connector cannot await. Rather than await the
    coroutine first -- which would run the tool before the gateway had permitted it -- the
    gateway's own frame is moved to a worker thread: its connector schedules the coroutine back
    onto the caller's loop and blocks that thread until it resolves. The tool therefore runs on the
    loop it was called from, inside the gateway's execution frame, and every ledger guarantee the
    sync path has (nothing runs before the permit, a raising tool records ``FAILED``) holds here
    unchanged.
    """

    async def call(self, input: object) -> str:
        arguments = _arguments(input)
        decision = self._decide(arguments)
        loop = asyncio.get_running_loop()

        def connector(call_arguments: Mapping[str, Any]) -> Any:
            return asyncio.run_coroutine_threadsafe(self._binding.function(call_arguments), loop).result()

        try:
            result = await asyncio.to_thread(
                self._gateway.execute_approved_call,
                decision.decision_id,
                arguments,
                connector,
                idempotency_key=str(uuid.uuid4()),
            )
        except InvocationBlocked as blocked:
            raise self._blocked(blocked.decision) from blocked
        return _serialise(result.value)


def _strongest_declared(actor: ActorSpec | None) -> SideEffect:
    if actor is None or not actor.side_effects:
        return SideEffect.NONE
    return max(actor.side_effects, key=side_effect_rank)


def bind_architecture(
    gateway: MCPToolGateway,
    graph_or_compiled: ArchitectureGraph | CompiledArchitecture,
    *,
    tool_bindings: Mapping[str, str] | None = None,
    approver: str,
) -> CompiledArchitecture:
    """Register a reviewed architecture's actors and link policies into ``gateway``.

    Registration is delegated to ``mcp_transport.bind_gateway_actors``, the same helper the MCP
    transport adapter binds through, so the two adapters cannot wire a graph differently. No
    revision is passed: ``guard_tools`` observes each definition afterwards and pins the actor to
    the digest it saw. Call this once, then :func:`guard_tools`.

    ``tool_bindings`` maps tool name to Tool actor id, exactly as the transport adapter's does;
    naming a tool whose actor is missing, is not a TOOL, or has no REL-05 edge is an error. Omitted,
    every TOOL actor that some REL-05 edge points at is bound -- the invocable tools -- and a TOOL
    actor nothing invokes is left alone rather than treated as a broken binding.
    """
    compiled = (
        graph_or_compiled
        if isinstance(graph_or_compiled, CompiledArchitecture)
        else ArchitectureCompiler().compile(graph_or_compiled)
    )
    if tool_bindings is not None:
        actor_ids: list[str] = list(dict.fromkeys(tool_bindings.values()))
    else:
        invoked = {edge.target for edge in compiled.graph.edges if edge.relationship_id == "REL-05"}
        actor_ids = [
            actor_id
            for actor_id, actor in compiled.actors.items()
            if actor.type == ActorType.TOOL and actor_id in invoked
        ]
    bind_gateway_actors(
        gateway,
        compiled,
        tool_revisions=dict.fromkeys(actor_ids),
        approver=approver,
    )
    return compiled


def guard_tools(
    gateway: MCPToolGateway,
    *,
    tenant_id: str,
    source_actor_id: str,
    bindings: Sequence[ToolBinding],
    approver: str,
    environment: Environment = Environment.DEV,
    data_source: DataSource = DataSource.PRODUCTION,
    classify: Classifier | None = None,
    credential: CredentialClaims | None = None,
    trace_id: str | None = None,
    approve: Approver | None = None,
) -> tuple[GuardedTool | GuardedAsyncTool, ...]:
    """Admit each definition and return the runnable tools to hand the tool runner.

    Per binding: observe the definition, approve and activate the revision, and pin the Tool actor
    to the digest that was observed. A tool actor the architecture already pinned keeps its pin --
    a disagreement between the pin and the observation is M2 drift, and letting the drift control
    say so at call time is the point of having it. An unpinned actor takes the observed digest, so
    the definition the model is shown is the definition the gateway will judge against.

    **A definition that does not reach ACTIVE raises.** ``registry.observe`` quarantines a
    description carrying an instruction (M1), a cross-server reference (M3) or an unsupported
    schema keyword, and ``registry.approve`` would accept a QUARANTINED revision, so refusing here
    is what keeps a poisoned tool out of the request the model sees. The alternative -- returning a
    tool that fails every call with ``L1-M2-DEFINITION-NOT-ACTIVE`` -- still ships the poisoned
    description to the model in ``tools``, which is the attack. Dropping it silently would leave a
    project one tool short with nothing said. So: raise, naming the tool and its reason codes.

    Actors and links must already be in the gateway, from :func:`bind_architecture` or from manual
    ``register_actor``/``connect`` calls; a missing actor or an unwired pair raises ``ValueError``
    naming it rather than failing later as a ``KeyError`` inside an invocation.

    A binding whose ``function`` is a coroutine function yields a :class:`GuardedAsyncTool`, which
    only the SDK's async runner can drive; anything else yields a :class:`GuardedTool`.
    """
    if gateway.actor(source_actor_id) is None:
        raise ValueError(f"source actor {source_actor_id!r} is not registered in the gateway")

    guarded: list[GuardedTool | GuardedAsyncTool] = []
    for binding in bindings:
        target = gateway.actor(binding.actor_id)
        if target is None:
            raise ValueError(f"Tool actor {binding.actor_id!r} is not registered in the gateway")
        if gateway.link_policy(source_actor_id, binding.actor_id) is None:
            raise ValueError(f"no link policy connects {source_actor_id!r} to {binding.actor_id!r}")

        revision = gateway.observe_definition(binding.definition, tenant_id=tenant_id, trace_id=trace_id)
        if revision.state == DefinitionState.DISCOVERED:
            revision = gateway.registry.approve(revision.revision_id, approver)
        if revision.state == DefinitionState.APPROVED:
            revision = gateway.registry.activate(revision.revision_id)
        if revision.state != DefinitionState.ACTIVE:
            reasons = ", ".join(revision.reason_codes) or "no reason code"
            raise ValueError(
                f"tool {binding.definition.tool_name!r} cannot be guarded: "
                f"definition is {revision.state.value} ({reasons})"
            )

        if target.definition_digest is None:
            target = replace(target, definition_digest=revision.canonical_digest)
        gateway.register_actor(target, tool_id=revision.tool_id)

        tool_class = GuardedAsyncTool if inspect.iscoroutinefunction(binding.function) else GuardedTool
        guarded.append(
            tool_class(
                gateway,
                binding,
                revision,
                tenant_id=tenant_id,
                source_actor_id=source_actor_id,
                environment=environment,
                data_source=data_source,
                classify=classify,
                credential=credential,
                trace_id=trace_id,
                approve=approve,
            )
        )
    return tuple(guarded)
