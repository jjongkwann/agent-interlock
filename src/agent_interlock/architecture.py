"""Architecture-as-Code model, security lint, compiler, and runtime drift analysis."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Any, Iterable, Mapping

from .ledger import Event, Ledger
from .models import (
    ActorSpec,
    ActorType,
    ControlDecision,
    FailureMode,
    LinkPolicy,
    PolicyMode,
    SideEffect,
)
from .sdk import Interlock


class SecurityObjective(StrEnum):
    PREVENT = "PREVENT"
    DETECT = "DETECT"
    RESPOND = "RESPOND"
    EVIDENCE = "EVIDENCE"


class ControlTiming(StrEnum):
    DESIGN = "DESIGN"
    ADMISSION = "ADMISSION"
    PRE_EXECUTION = "PRE_EXECUTION"
    EXECUTION = "EXECUTION"
    POST_EXECUTION = "POST_EXECUTION"


class EnforcementPoint(StrEnum):
    DESIGN_LINTER = "DESIGN_LINTER"
    SDK = "SDK"
    INPUT_GATEWAY = "INPUT_GATEWAY"
    MODEL_ROUTER = "MODEL_ROUTER"
    RAG_GATEWAY = "RAG_GATEWAY"
    MCP_GATEWAY = "MCP_GATEWAY"
    A2A_BROKER = "A2A_BROKER"
    MEMORY_STORE = "MEMORY_STORE"
    EGRESS_GATEWAY = "EGRESS_GATEWAY"
    APPROVAL_GATE = "APPROVAL_GATE"
    TRIGGER_VALIDATOR = "TRIGGER_VALIDATOR"
    STATE_MACHINE = "STATE_MACHINE"
    SANDBOX = "SANDBOX"
    DEPLOY_GATE = "DEPLOY_GATE"
    AUDIT_SINK = "AUDIT_SINK"
    RESPONSE_ORCHESTRATOR = "RESPONSE_ORCHESTRATOR"


class AssuranceLevel(StrEnum):
    DECLARED = "DECLARED"
    OBSERVED = "OBSERVED"
    ENFORCED = "ENFORCED"
    RECONCILED = "RECONCILED"


class FindingSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class SecurityControl:
    id: str
    objective: SecurityObjective
    timing: ControlTiming
    enforcement_point: EnforcementPoint
    assurance: AssuranceLevel
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("security control id is required")


@dataclass(frozen=True, slots=True)
class ArchitectureNode:
    actor: ActorSpec
    controls: tuple[SecurityControl, ...] = ()
    position: tuple[float, float] | None = None

    @property
    def id(self) -> str:
        return self.actor.id


@dataclass(frozen=True, slots=True)
class DynamicTargetSelector:
    actor_types: frozenset[ActorType]
    required_capabilities: frozenset[str] = frozenset()
    id_pattern: str = "*"
    same_tenant: bool = True

    def __post_init__(self) -> None:
        if not self.actor_types:
            raise ValueError("dynamic target selector requires at least one Actor type")
        if not self.id_pattern:
            raise ValueError("dynamic target selector id_pattern is required")


@dataclass(frozen=True, slots=True)
class ArchitectureEdge:
    id: str
    relationship_id: str
    source: str
    target: str
    relationship: str
    policy: LinkPolicy
    controls: tuple[SecurityControl, ...] = ()
    dynamic: bool = False
    target_selector: DynamicTargetSelector | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.relationship_id or not self.source or not self.target:
            raise ValueError("edge id, relationship_id, source, and target are required")
        if self.dynamic and self.target_selector is None:
            raise ValueError("dynamic edge requires a target selector")
        if not self.dynamic and self.target_selector is not None:
            raise ValueError("target selector is only valid for a dynamic edge")


@dataclass(frozen=True, slots=True)
class ArchitectureGraph:
    id: str
    version: str
    nodes: tuple[ArchitectureNode, ...]
    edges: tuple[ArchitectureEdge, ...]
    api_version: str = "interlock.dev/v1alpha1"

    def __post_init__(self) -> None:
        if not self.id or not self.version:
            raise ValueError("architecture id and version are required")
        node_ids = [node.id for node in self.nodes]
        edge_ids = [edge.id for edge in self.edges]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("architecture node ids must be unique")
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("architecture edge ids must be unique")
        known = set(node_ids)
        control_ids: list[str] = []
        control_ids.extend(control.id for node in self.nodes for control in node.controls)
        for edge in self.edges:
            if edge.source not in known or edge.target not in known:
                raise ValueError(f"edge {edge.id} references an unknown node")
            control_ids.extend(control.id for control in edge.controls)
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("security control ids must be unique within an architecture")

    @property
    def node_map(self) -> dict[str, ArchitectureNode]:
        return {node.id: node for node in self.nodes}

    @classmethod
    def from_dict(cls, manifest: Mapping[str, Any]) -> "ArchitectureGraph":
        if manifest.get("apiVersion") != "interlock.dev/v1alpha1":
            raise ValueError("manifest apiVersion must be interlock.dev/v1alpha1")
        if manifest.get("kind") != "Architecture":
            raise ValueError("manifest kind must be Architecture")
        metadata = _mapping(manifest.get("metadata"), "metadata")
        spec = _mapping(manifest.get("spec"), "spec")
        nodes = tuple(_parse_node(item) for item in _sequence(spec.get("nodes"), "spec.nodes"))
        node_types = {node.id: node.actor.type for node in nodes}
        edges = tuple(
            _parse_edge(item, node_types) for item in _sequence(spec.get("edges"), "spec.edges")
        )
        return cls(
            id=_required_string(metadata, "id"),
            version=_required_string(metadata, "version"),
            nodes=nodes,
            edges=edges,
            api_version=str(manifest.get("apiVersion", "interlock.dev/v1alpha1")),
        )

    def to_design_graph(self) -> dict[str, Any]:
        return {
            "architectureId": self.id,
            "version": self.version,
            "nodes": [
                {
                    "id": node.id,
                    "type": node.actor.type.value,
                    "owner": node.actor.owner,
                    "position": node.position,
                    "controls": [_control_value(control) for control in node.controls],
                }
                for node in self.nodes
            ],
            "edges": [
                {
                    "id": edge.id,
                    "relationshipId": edge.relationship_id,
                    "source": edge.source,
                    "target": edge.target,
                    "relationship": edge.relationship,
                    "mode": edge.policy.mode.value,
                    "dynamic": edge.dynamic,
                    "targetSelector": (
                        {
                            "types": sorted(item.value for item in edge.target_selector.actor_types),
                            "requiredCapabilities": sorted(edge.target_selector.required_capabilities),
                            "idPattern": edge.target_selector.id_pattern,
                            "sameTenant": edge.target_selector.same_tenant,
                        }
                        if edge.target_selector
                        else None
                    ),
                    "controls": [_control_value(control) for control in edge.controls],
                }
                for edge in self.edges
            ],
        }


@dataclass(frozen=True, slots=True)
class ArchitectureFinding:
    code: str
    severity: FindingSeverity
    message: str
    edge_id: str | None = None
    node_id: str | None = None
    remediation: str = ""


@dataclass(frozen=True, slots=True)
class CompiledArchitecture:
    graph: ArchitectureGraph
    actors: Mapping[str, ActorSpec]
    links: Mapping[str, LinkPolicy]
    findings: tuple[ArchitectureFinding, ...]

    def build_interlock(self, ledger: Ledger | None = None) -> Interlock:
        runtime = Interlock(ledger)
        actor_handles = {
            actor_id: runtime.define_actor(actor) for actor_id, actor in self.actors.items()
        }
        for edge in self.graph.edges:
            actor_handles[edge.source].connect(actor_handles[edge.target], self.links[edge.id])
        return runtime


class ArchitectureCompileError(ValueError):
    def __init__(self, findings: tuple[ArchitectureFinding, ...]):
        self.findings = findings
        codes = ", ".join(item.code for item in findings if item.severity == FindingSeverity.CRITICAL)
        super().__init__(f"architecture has critical security findings: {codes}")


class ArchitectureLinter:
    _required_points = {
        "REL-01": EnforcementPoint.INPUT_GATEWAY,
        "REL-03": EnforcementPoint.RAG_GATEWAY,
        "REL-05": EnforcementPoint.MCP_GATEWAY,
        "REL-06": EnforcementPoint.A2A_BROKER,
        "REL-07": EnforcementPoint.EGRESS_GATEWAY,
        "REL-12": EnforcementPoint.AUDIT_SINK,
    }
    _high_risk_relationships = frozenset({"REL-03", "REL-05", "REL-06", "REL-07"})
    _expected_relationships = {
        "REL-01": "REQUESTS",
        "REL-03": "READS",
        "REL-05": "INVOKES",
        "REL-06": "DELEGATES",
        "REL-07": "SENDS",
        "REL-12": "LOGS_TO",
    }

    def lint(self, graph: ArchitectureGraph) -> tuple[ArchitectureFinding, ...]:
        findings: list[ArchitectureFinding] = []
        nodes = graph.node_map
        for edge in graph.edges:
            findings.extend(self._lint_edge(edge, nodes))
        findings.extend(self._delegation_cycles(graph))
        return tuple(findings)

    def _lint_edge(
        self, edge: ArchitectureEdge, nodes: Mapping[str, ArchitectureNode]
    ) -> list[ArchitectureFinding]:
        findings: list[ArchitectureFinding] = []
        source = nodes[edge.source].actor
        target = nodes[edge.target].actor
        expected_relationship = self._expected_relationships.get(edge.relationship_id)
        if expected_relationship and edge.relationship != expected_relationship:
            findings.append(
                ArchitectureFinding(
                    "ARCH-RELATIONSHIP-ID-MISMATCH",
                    FindingSeverity.CRITICAL,
                    f"{edge.relationship_id} requires relationship {expected_relationship}",
                    edge_id=edge.id,
                )
            )
        if not edge.controls:
            findings.append(
                ArchitectureFinding(
                    "ARCH-CONTROL-MISSING",
                    FindingSeverity.CRITICAL,
                    "relationship has no declared security control",
                    edge_id=edge.id,
                    remediation="Attach a control with an explicit enforcement point and assurance level.",
                )
            )
            return findings

        required = self._required_points.get(edge.relationship_id)
        acceptable_assurance = (
            {AssuranceLevel.OBSERVED, AssuranceLevel.ENFORCED, AssuranceLevel.RECONCILED}
            if edge.relationship_id == "REL-12"
            else {AssuranceLevel.ENFORCED, AssuranceLevel.RECONCILED}
        )
        if required and not any(
            control.enforcement_point == required
            and control.assurance in acceptable_assurance
            for control in edge.controls
        ):
            findings.append(
                ArchitectureFinding(
                    "ARCH-ENFORCEMENT-POINT-MISSING",
                    FindingSeverity.CRITICAL,
                    f"{edge.relationship_id} requires {required.value} with enforced assurance",
                    edge_id=edge.id,
                    remediation=f"Add an ENFORCED control at {required.value}.",
                )
            )
        if not any(control.enforcement_point == EnforcementPoint.AUDIT_SINK for control in edge.controls):
            findings.append(
                ArchitectureFinding(
                    "ARCH-AUDIT-GAP",
                    FindingSeverity.WARNING,
                    "relationship has no explicit audit evidence control",
                    edge_id=edge.id,
                    remediation="Attach an OBSERVED or RECONCILED AUDIT_SINK control.",
                )
            )
        for control in edge.controls:
            if control.assurance == AssuranceLevel.DECLARED:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-DECLARED-ONLY",
                        FindingSeverity.WARNING,
                        f"control {control.id} is declared but has no runtime assurance",
                        edge_id=edge.id,
                        remediation="Connect the declared control to an enforcement or observation adapter.",
                    )
                )
            if control.objective == SecurityObjective.PREVENT and control.timing == ControlTiming.POST_EXECUTION:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-PREVENT-AFTER-EXECUTION",
                        FindingSeverity.CRITICAL,
                        f"control {control.id} cannot prevent an action after execution",
                        edge_id=edge.id,
                        remediation="Move it to PRE_EXECUTION or change the objective to DETECT/RESPOND.",
                    )
                )

        if "D5" in edge.policy.allowed_data_classes:
            findings.append(
                ArchitectureFinding(
                    "ARCH-CREDENTIAL-DATA-ALLOWED",
                    FindingSeverity.CRITICAL,
                    "credential data class D5 is allowed across the relationship",
                    edge_id=edge.id,
                    remediation="Deny D5 and use opaque credential references with a credential broker.",
                )
            )
        if edge.relationship_id in self._high_risk_relationships:
            if edge.policy.mode == PolicyMode.OBSERVE:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-HIGH-RISK-OBSERVE-ONLY",
                        FindingSeverity.HIGH,
                        "high-risk relationship is configured as OBSERVE only",
                        edge_id=edge.id,
                        remediation="Validate in SHADOW and promote the policy to ENFORCE.",
                    )
                )
            if edge.policy.failure_mode == FailureMode.FAIL_OPEN:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-HIGH-RISK-FAIL-OPEN",
                        FindingSeverity.CRITICAL,
                        "high-risk relationship fails open",
                        edge_id=edge.id,
                        remediation="Use FAIL_CLOSED or DEGRADE_READ_ONLY.",
                    )
                )

        if edge.relationship_id == "REL-03" and target.type != ActorType.RAG:
            findings.append(self._type_finding(edge, "REL-03 target must be RAG"))
        if edge.relationship_id == "REL-03" and target.tenant_mode != "REQUIRED":
            findings.append(
                ArchitectureFinding(
                    "ARCH-RAG-TENANT-OPTIONAL",
                    FindingSeverity.CRITICAL,
                    "RAG security boundary must require a tenant",
                    edge_id=edge.id,
                )
            )
        if edge.relationship_id == "REL-05":
            if target.type != ActorType.TOOL:
                findings.append(self._type_finding(edge, "REL-05 target must be TOOL"))
            if edge.policy.require_digest_pin and not target.definition_digest:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-TOOL-DIGEST-UNPINNED",
                        FindingSeverity.CRITICAL,
                        "Tool relationship requires digest pinning but the Tool has no definition digest",
                        edge_id=edge.id,
                    )
                )
        if edge.relationship_id == "REL-06":
            if source.type not in {ActorType.AGENT, ActorType.SUBAGENT} or target.type not in {
                ActorType.AGENT,
                ActorType.SUBAGENT,
            }:
                findings.append(self._type_finding(edge, "REL-06 must connect Agent/Sub-Agent actors"))
            if edge.policy.max_delegation_depth < 1:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-DELEGATION-DISABLED",
                        FindingSeverity.CRITICAL,
                        "delegation edge has maxDelegationDepth below one",
                        edge_id=edge.id,
                    )
                )
            if edge.policy.max_delegation_depth > source.max_delegation_depth:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-DELEGATION-DEPTH-EXCEEDS-ACTOR",
                        FindingSeverity.CRITICAL,
                        "LinkPolicy delegation depth exceeds the source Actor limit",
                        edge_id=edge.id,
                    )
                )
            if not (
                edge.policy.require_actor_binding
                and edge.policy.require_audience
                and edge.policy.require_resource
            ):
                findings.append(
                    ArchitectureFinding(
                        "ARCH-DELEGATION-BINDING-WEAK",
                        FindingSeverity.CRITICAL,
                        "delegation must bind actor, audience, and resource",
                        edge_id=edge.id,
                    )
                )
            if edge.dynamic and edge.target_selector:
                if not edge.target_selector.required_capabilities:
                    findings.append(
                        ArchitectureFinding(
                            "ARCH-DYNAMIC-CAPABILITY-UNBOUNDED",
                            FindingSeverity.CRITICAL,
                            "dynamic delegation selector has no required capability boundary",
                            edge_id=edge.id,
                        )
                    )
                if edge.target_selector.id_pattern == "*":
                    findings.append(
                        ArchitectureFinding(
                            "ARCH-DYNAMIC-TARGET-UNBOUNDED",
                            FindingSeverity.CRITICAL,
                            "dynamic delegation target ID pattern is unbounded",
                            edge_id=edge.id,
                        )
                    )
                if not edge.target_selector.same_tenant:
                    findings.append(
                        ArchitectureFinding(
                            "ARCH-DYNAMIC-DELEGATION-CROSS-TENANT",
                            FindingSeverity.CRITICAL,
                            "dynamic delegation permits a target outside the source tenant",
                            edge_id=edge.id,
                        )
                    )
                if not edge.target_selector.actor_types <= {
                    ActorType.AGENT,
                    ActorType.SUBAGENT,
                }:
                    findings.append(
                        ArchitectureFinding(
                            "ARCH-DYNAMIC-DELEGATION-TYPE",
                            FindingSeverity.CRITICAL,
                            "dynamic delegation selector includes a non-Agent Actor type",
                            edge_id=edge.id,
                        )
                    )
                if not edge.target_selector.required_capabilities <= target.capabilities:
                    findings.append(
                        ArchitectureFinding(
                            "ARCH-DYNAMIC-CAPABILITY-TEMPLATE-MISMATCH",
                            FindingSeverity.CRITICAL,
                            "dynamic selector capabilities are not declared by the target template",
                            edge_id=edge.id,
                        )
                    )
        if edge.relationship_id == "REL-07":
            if target.type != ActorType.EXTERNAL:
                findings.append(self._type_finding(edge, "REL-07 target must be EXTERNAL"))
            if not target.allowed_domains:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-EGRESS-DESTINATION-UNBOUNDED",
                        FindingSeverity.CRITICAL,
                        "external destination has no allowed domain boundary",
                        edge_id=edge.id,
                    )
                )
            if not edge.policy.require_explicit_destination:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-EGRESS-DESTINATION-IMPLICIT",
                        FindingSeverity.CRITICAL,
                        "external write does not require an explicit destination",
                        edge_id=edge.id,
                    )
                )
        return findings

    @staticmethod
    def _type_finding(edge: ArchitectureEdge, message: str) -> ArchitectureFinding:
        return ArchitectureFinding(
            "ARCH-RELATIONSHIP-TYPE-MISMATCH",
            FindingSeverity.CRITICAL,
            message,
            edge_id=edge.id,
        )

    def _delegation_cycles(self, graph: ArchitectureGraph) -> list[ArchitectureFinding]:
        adjacency: dict[str, set[str]] = {}
        for edge in graph.edges:
            if edge.relationship_id == "REL-06":
                adjacency.setdefault(edge.source, set()).add(edge.target)
        visiting: set[str] = set()
        visited: set[str] = set()
        findings: list[ArchitectureFinding] = []

        def visit(node: str) -> None:
            if node in visiting:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-DELEGATION-CYCLE",
                        FindingSeverity.HIGH,
                        f"delegation cycle detected at {node}",
                        node_id=node,
                        remediation="Break the cycle or require a strict decreasing delegation budget.",
                    )
                )
                return
            if node in visited:
                return
            visiting.add(node)
            for target in adjacency.get(node, set()):
                visit(target)
            visiting.remove(node)
            visited.add(node)

        for node in adjacency:
            visit(node)
        return findings


class ArchitectureCompiler:
    def __init__(self, linter: ArchitectureLinter | None = None) -> None:
        self.linter = linter or ArchitectureLinter()

    def compile(self, graph: ArchitectureGraph, *, reject_critical: bool = True) -> CompiledArchitecture:
        findings = self.linter.lint(graph)
        if reject_critical and any(item.severity == FindingSeverity.CRITICAL for item in findings):
            raise ArchitectureCompileError(findings)
        actors = {node.id: node.actor for node in graph.nodes}
        links = {
            edge.id: replace(
                edge.policy,
                id=edge.policy.id or edge.id,
                relationship=edge.relationship,
                source_types=frozenset({actors[edge.source].type}),
                target_types=frozenset({actors[edge.target].type}),
            )
            for edge in graph.edges
        }
        return CompiledArchitecture(graph=graph, actors=actors, links=links, findings=findings)


@dataclass(frozen=True, slots=True)
class ObservedEdge:
    source: str
    target: str
    relationship: str
    relationship_id: str
    interaction_id: str | None


@dataclass(frozen=True, slots=True)
class RuntimeGraphDiff:
    undeclared_edges: tuple[ObservedEdge, ...]
    unobserved_edge_ids: tuple[str, ...]
    control_bypass_interactions: tuple[str, ...]

    @property
    def conforms(self) -> bool:
        return not self.undeclared_edges and not self.control_bypass_interactions


def compare_runtime(graph: ArchitectureGraph, events: Iterable[Event]) -> RuntimeGraphDiff:
    event_list = tuple(events)
    observed: list[ObservedEdge] = []
    for event in event_list:
        if event.event_type != "INTERACTION_REQUESTED" or not event.target_actor_id:
            continue
        item = ObservedEdge(
            event.source_actor_id,
            event.target_actor_id,
            event.relationship_type,
            event.relationship_id,
            event.interaction_id,
        )
        observed.append(item)
    evaluated = {
        event.interaction_id
        for event in event_list
        if event.event_type == "CONTROL_EVALUATED" and event.interaction_id
    }
    return compare_observed_runtime(graph, observed, evaluated)


def compare_observed_runtime(
    graph: ArchitectureGraph,
    observations: Iterable[ObservedEdge],
    control_evaluated_interactions: Iterable[str] = (),
) -> RuntimeGraphDiff:
    observed = tuple(observations)

    def matches(edge: ArchitectureEdge, item: ObservedEdge) -> bool:
        if (
            edge.source != item.source
            or edge.relationship != item.relationship
            or edge.relationship_id != item.relationship_id
        ):
            return False
        if not edge.dynamic:
            return edge.target == item.target
        return bool(
            edge.target_selector and fnmatchcase(item.target, edge.target_selector.id_pattern)
        )

    undeclared = tuple(item for item in observed if not any(matches(edge, item) for edge in graph.edges))
    unobserved = tuple(
        edge.id for edge in graph.edges if not any(matches(edge, item) for item in observed)
    )
    evaluated = set(control_evaluated_interactions)
    bypass = tuple(
        dict.fromkeys(
            item.interaction_id
            for item in observed
            if item.interaction_id and item.interaction_id not in evaluated
        )
    )
    return RuntimeGraphDiff(undeclared, unobserved, bypass)


def _parse_node(value: Any) -> ArchitectureNode:
    item = _mapping(value, "node")
    position_value = item.get("position")
    position = None
    if position_value is not None:
        position_map = _mapping(position_value, "node.position")
        position = (float(position_map.get("x", 0)), float(position_map.get("y", 0)))
    return ArchitectureNode(
        actor=ActorSpec(
            id=_required_string(item, "id"),
            type=ActorType(_required_string(item, "type")),
            owner=_required_string(item, "owner"),
            identity=_required_string(item, "identity"),
            capabilities=frozenset(_strings(item.get("capabilities", []), "capabilities")),
            data_access=frozenset(_strings(item.get("dataAccess", []), "dataAccess")),
            side_effects=frozenset(
                SideEffect(value) for value in _strings(item.get("sideEffects", []), "sideEffects")
            ),
            input_schema=_mapping(item.get("inputSchema", {}), "inputSchema"),
            output_schema=_mapping(item.get("outputSchema", {}), "outputSchema"),
            tenant_mode=str(item.get("tenantMode", "REQUIRED")),
            failure_mode=FailureMode(str(item.get("failureMode", "FAIL_CLOSED"))),
            allowed_domains=frozenset(_strings(item.get("allowedDomains", []), "allowedDomains")),
            max_delegation_depth=int(item.get("maxDelegationDepth", 1)),
            definition_digest=item.get("definitionDigest"),
        ),
        controls=tuple(_parse_control(control) for control in _sequence(item.get("controls", []), "controls")),
        position=position,
    )


def _parse_edge(value: Any, node_types: Mapping[str, ActorType]) -> ArchitectureEdge:
    item = _mapping(value, "edge")
    source = _required_string(item, "source")
    target = _required_string(item, "target")
    policy_value = _mapping(item.get("policy", {}), "edge.policy")
    policy = LinkPolicy(
        id=str(policy_value.get("id", item.get("id", "architecture-link"))),
        version=str(policy_value.get("version", "1.0.0")),
        mode=PolicyMode(str(policy_value.get("mode", "SHADOW"))),
        source_types=frozenset({node_types[source]}) if source in node_types else frozenset(),
        target_types=frozenset({node_types[target]}) if target in node_types else frozenset(),
        relationship=_required_string(item, "relationship"),
        allowed_purposes=frozenset(_strings(policy_value.get("allowedPurposes", []), "allowedPurposes")),
        allowed_data_classes=frozenset(
            _strings(policy_value.get("allowedDataClasses", ["D2", "D3", "D7"]), "allowedDataClasses")
        ),
        denied_data_classes=frozenset(
            _strings(policy_value.get("deniedDataClasses", ["D5", "D8"]), "deniedDataClasses")
        ),
        require_active_definition=bool(policy_value.get("requireActiveDefinition", True)),
        require_digest_pin=bool(policy_value.get("requireDigestPin", True)),
        require_explicit_destination=bool(policy_value.get("requireExplicitDestination", True)),
        new_destination_action=ControlDecision(str(policy_value.get("newDestinationAction", "HOLD"))),
        token_passthrough=bool(policy_value.get("tokenPassthrough", False)),
        require_audience=bool(policy_value.get("requireAudience", True)),
        require_resource=bool(policy_value.get("requireResource", True)),
        require_actor_binding=bool(policy_value.get("requireActorBinding", True)),
        max_delegation_depth=int(policy_value.get("maxDelegationDepth", 1)),
        external_write_requires_approval=bool(
            policy_value.get("externalWriteRequiresApproval", True)
        ),
        failure_mode=FailureMode(str(policy_value.get("failureMode", "FAIL_CLOSED"))),
        decision_ttl_seconds=int(policy_value.get("decisionTtlSeconds", 30)),
    )
    dynamic = bool(item.get("dynamic", False))
    selector_value = item.get("targetSelector")
    selector = None
    if selector_value is not None:
        selector_map = _mapping(selector_value, "edge.targetSelector")
        selector = DynamicTargetSelector(
            actor_types=frozenset(
                ActorType(value)
                for value in _strings(selector_map.get("types", []), "targetSelector.types")
            ),
            required_capabilities=frozenset(
                _strings(
                    selector_map.get("requiredCapabilities", []),
                    "targetSelector.requiredCapabilities",
                )
            ),
            id_pattern=str(selector_map.get("idPattern", "*")),
            same_tenant=bool(selector_map.get("sameTenant", True)),
        )
    return ArchitectureEdge(
        id=_required_string(item, "id"),
        relationship_id=_required_string(item, "relationshipId"),
        source=source,
        target=target,
        relationship=policy.relationship,
        policy=policy,
        controls=tuple(_parse_control(control) for control in _sequence(item.get("controls", []), "controls")),
        dynamic=dynamic,
        target_selector=selector,
    )


def _parse_control(value: Any) -> SecurityControl:
    item = _mapping(value, "control")
    return SecurityControl(
        id=_required_string(item, "id"),
        objective=SecurityObjective(_required_string(item, "objective")),
        timing=ControlTiming(_required_string(item, "timing")),
        enforcement_point=EnforcementPoint(_required_string(item, "enforcementPoint")),
        assurance=AssuranceLevel(_required_string(item, "assurance")),
        description=str(item.get("description", "")),
    )


def _control_value(control: SecurityControl) -> dict[str, str]:
    return {
        "id": control.id,
        "objective": control.objective.value,
        "timing": control.timing.value,
        "enforcementPoint": control.enforcement_point.value,
        "assurance": control.assurance.value,
        "description": control.description,
    }


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _sequence(value: Any, name: str) -> list[Any] | tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be an array")
    return value


def _strings(value: Any, name: str) -> tuple[str, ...]:
    sequence = _sequence(value, name)
    if not all(isinstance(item, str) for item in sequence):
        raise ValueError(f"{name} must contain only strings")
    return tuple(sequence)


def _required_string(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a non-empty string")
    return item
