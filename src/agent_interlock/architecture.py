"""Architecture-as-Code model, security lint, compiler, and runtime drift analysis."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Any

from .ledger import Event, Ledger
from .models import ActorSpec, ActorType, ControlDecision, FailureMode, LinkPolicy, PolicyMode, SideEffect
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


class TrustZone(StrEnum):
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"


class OrchestrationPattern(StrEnum):
    STATE_GRAPH = "STATE_GRAPH"
    HIERARCHICAL = "HIERARCHICAL"
    CONVERSATIONAL = "CONVERSATIONAL"
    HYBRID = "HYBRID"


class TaskTransport(StrEnum):
    A2A = "A2A"
    MCP = "MCP"
    LOCAL = "LOCAL"
    HUMAN = "HUMAN"


class TaskFailureAction(StrEnum):
    FAIL_WORKFLOW = "FAIL_WORKFLOW"
    SKIP = "SKIP"
    CONTINUE = "CONTINUE"


@dataclass(frozen=True, slots=True)
class ArchitectureTrustZone:
    id: str
    label: str
    kind: TrustZone
    bounds: tuple[float, float, float, float]
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id or not self.label:
            raise ValueError("trust zone id and label are required")
        if self.bounds[0] < 0 or self.bounds[1] < 0 or self.bounds[2] <= 0 or self.bounds[3] <= 0:
            raise ValueError("trust zone bounds require non-negative x/y and positive width/height")


@dataclass(frozen=True, slots=True)
class ArchitectureBoundary:
    """One directional policy boundary between two trust zones.

    A boundary is deliberately separate from a visual zone rectangle.  It is
    the executable contract that an edge must cross, and is compiled for use
    by protocol gateways such as the A2A broker.
    """

    id: str
    label: str
    source_zone_id: str
    target_zone_id: str
    enforcement_point: EnforcementPoint
    allowed_relationships: frozenset[str]
    allowed_data_classes: frozenset[str] = frozenset({"D2", "D3", "D7"})
    denied_data_classes: frozenset[str] = frozenset({"D5", "D8"})
    mode: PolicyMode = PolicyMode.ENFORCE
    failure_mode: FailureMode = FailureMode.FAIL_CLOSED
    require_identity: bool = True
    require_tenant_binding: bool = True
    max_payload_bytes: int = 1_048_576
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id or not self.label or not self.source_zone_id or not self.target_zone_id:
            raise ValueError("boundary id, label, source zone, and target zone are required")
        if self.source_zone_id == self.target_zone_id:
            raise ValueError("a trust boundary must connect two different zones")
        if not self.allowed_relationships:
            raise ValueError("a trust boundary requires at least one allowed relationship")
        if self.allowed_data_classes & self.denied_data_classes:
            raise ValueError("boundary data classes cannot be both allowed and denied")
        if self.max_payload_bytes <= 0:
            raise ValueError("boundary max_payload_bytes must be positive")


@dataclass(frozen=True, slots=True)
class OrchestrationTask:
    id: str
    label: str
    source_actor_id: str
    target_actor_id: str
    transport: TaskTransport
    purpose: str
    depends_on: tuple[str, ...] = ()
    data_classes: frozenset[str] = frozenset({"D3"})
    acceptance_criteria: tuple[str, ...] = ()
    max_attempts: int = 1
    timeout_seconds: int = 300
    approval_required: bool = False
    on_failure: TaskFailureAction = TaskFailureAction.FAIL_WORKFLOW
    position: tuple[float, float] | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.label or not self.source_actor_id or not self.target_actor_id or not self.purpose:
            raise ValueError("task id, label, source, target, and purpose are required")
        if self.id in self.depends_on:
            raise ValueError("an orchestration task cannot depend on itself")
        if len(self.depends_on) != len(set(self.depends_on)):
            raise ValueError("orchestration task dependencies must be unique")
        if self.max_attempts < 1:
            raise ValueError("task max_attempts must be at least one")
        if self.timeout_seconds < 1:
            raise ValueError("task timeout_seconds must be positive")


@dataclass(frozen=True, slots=True)
class OrchestrationRunPolicy:
    max_parallelism: int = 4
    max_tasks: int = 100
    max_duration_seconds: int = 3600
    max_messages: int = 500
    fail_fast: bool = True

    def __post_init__(self) -> None:
        if min(self.max_parallelism, self.max_tasks, self.max_duration_seconds, self.max_messages) < 1:
            raise ValueError("orchestration run-policy limits must be positive")
        if self.max_parallelism > self.max_tasks:
            raise ValueError("max_parallelism cannot exceed max_tasks")


@dataclass(frozen=True, slots=True)
class OrchestrationDefinition:
    coordinator_actor_id: str
    pattern: OrchestrationPattern
    tasks: tuple[OrchestrationTask, ...]
    run_policy: OrchestrationRunPolicy = OrchestrationRunPolicy()

    def __post_init__(self) -> None:
        if not self.coordinator_actor_id:
            raise ValueError("orchestration coordinator_actor_id is required")
        task_ids = [task.id for task in self.tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("orchestration task ids must be unique")
        known = set(task_ids)
        for task in self.tasks:
            missing = set(task.depends_on) - known
            if missing:
                raise ValueError(f"task {task.id} references unknown dependencies: {', '.join(sorted(missing))}")
        if len(self.tasks) > self.run_policy.max_tasks:
            raise ValueError("orchestration task count exceeds run policy max_tasks")
        _validate_acyclic_tasks(self.tasks)


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
    trust_zone: TrustZone | None = None
    trust_zone_id: str | None = None

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
    boundary_id: str | None = None

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
    trust_zones: tuple[ArchitectureTrustZone, ...] = ()
    boundaries: tuple[ArchitectureBoundary, ...] = ()
    orchestration: OrchestrationDefinition | None = None
    api_version: str = "interlock.dev/v1alpha1"

    def __post_init__(self) -> None:
        if not self.id or not self.version:
            raise ValueError("architecture id and version are required")
        node_ids = [node.id for node in self.nodes]
        edge_ids = [edge.id for edge in self.edges]
        zone_ids = [zone.id for zone in self.trust_zones]
        boundary_ids = [boundary.id for boundary in self.boundaries]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("architecture node ids must be unique")
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("architecture edge ids must be unique")
        if len(zone_ids) != len(set(zone_ids)):
            raise ValueError("architecture trust zone ids must be unique")
        if len(boundary_ids) != len(set(boundary_ids)):
            raise ValueError("architecture boundary ids must be unique")
        zone_map = {zone.id: zone for zone in self.trust_zones}
        for boundary in self.boundaries:
            if boundary.source_zone_id not in zone_map or boundary.target_zone_id not in zone_map:
                raise ValueError(f"boundary {boundary.id} references an unknown trust zone")
        for node in self.nodes:
            if node.trust_zone_id is None:
                continue
            if node.trust_zone_id not in zone_map:
                raise ValueError(f"node {node.id} references an unknown trust zone")
            if node.trust_zone is not None and node.trust_zone != zone_map[node.trust_zone_id].kind:
                raise ValueError(f"node {node.id} trust zone kind does not match its referenced zone")
        known = set(node_ids)
        control_ids: list[str] = []
        control_ids.extend(control.id for node in self.nodes for control in node.controls)
        for edge in self.edges:
            if edge.source not in known or edge.target not in known:
                raise ValueError(f"edge {edge.id} references an unknown node")
            if edge.boundary_id is not None and edge.boundary_id not in set(boundary_ids):
                raise ValueError(f"edge {edge.id} references an unknown trust boundary")
            control_ids.extend(control.id for control in edge.controls)
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("security control ids must be unique within an architecture")
        if self.orchestration is not None:
            if self.orchestration.coordinator_actor_id not in known:
                raise ValueError("orchestration coordinator references an unknown actor")
            for task in self.orchestration.tasks:
                if task.source_actor_id not in known or task.target_actor_id not in known:
                    raise ValueError(f"orchestration task {task.id} references an unknown actor")

    @property
    def node_map(self) -> dict[str, ArchitectureNode]:
        return {node.id: node for node in self.nodes}

    @classmethod
    def from_dict(cls, manifest: Mapping[str, Any]) -> ArchitectureGraph:
        if manifest.get("apiVersion") != "interlock.dev/v1alpha1":
            raise ValueError("manifest apiVersion must be interlock.dev/v1alpha1")
        if manifest.get("kind") != "Architecture":
            raise ValueError("manifest kind must be Architecture")
        metadata = _mapping(manifest.get("metadata"), "metadata")
        spec = _mapping(manifest.get("spec"), "spec")
        trust_zones = tuple(
            _parse_trust_zone(item) for item in _sequence(spec.get("trustZones", []), "spec.trustZones")
        )
        boundaries = tuple(
            _parse_boundary(item) for item in _sequence(spec.get("trustBoundaries", []), "spec.trustBoundaries")
        )
        nodes = tuple(_parse_node(item) for item in _sequence(spec.get("nodes"), "spec.nodes"))
        node_types = {node.id: node.actor.type for node in nodes}
        edges = tuple(_parse_edge(item, node_types) for item in _sequence(spec.get("edges"), "spec.edges"))
        orchestration_value = spec.get("orchestration")
        return cls(
            id=_required_string(metadata, "id"),
            version=_required_string(metadata, "version"),
            nodes=nodes,
            edges=edges,
            trust_zones=trust_zones,
            boundaries=boundaries,
            orchestration=_parse_orchestration(orchestration_value) if orchestration_value is not None else None,
            api_version=str(manifest.get("apiVersion", "interlock.dev/v1alpha1")),
        )

    def to_design_graph(self) -> dict[str, Any]:
        return {
            "architectureId": self.id,
            "version": self.version,
            "trustZones": [
                {
                    "id": zone.id,
                    "label": zone.label,
                    "kind": zone.kind.value,
                    "description": zone.description,
                    "bounds": {
                        "x": zone.bounds[0],
                        "y": zone.bounds[1],
                        "width": zone.bounds[2],
                        "height": zone.bounds[3],
                    },
                }
                for zone in self.trust_zones
            ],
            "trustBoundaries": [_boundary_value(boundary) for boundary in self.boundaries],
            "nodes": [
                {
                    "id": node.id,
                    "type": node.actor.type.value,
                    "owner": node.actor.owner,
                    "position": node.position,
                    **({"trustZone": node.trust_zone.value} if node.trust_zone else {}),
                    **({"trustZoneId": node.trust_zone_id} if node.trust_zone_id else {}),
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
                    "boundaryId": edge.boundary_id,
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
            "orchestration": _orchestration_value(self.orchestration) if self.orchestration else None,
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
    boundaries: Mapping[str, ArchitectureBoundary]
    findings: tuple[ArchitectureFinding, ...]

    def build_interlock(self, ledger: Ledger | None = None) -> Interlock:
        runtime = Interlock(ledger)
        actor_handles = {actor_id: runtime.define_actor(actor) for actor_id, actor in self.actors.items()}
        for edge in self.graph.edges:
            actor_handles[edge.source].connect(actor_handles[edge.target], self.links[edge.id])
        return runtime

    def edge_for(self, source_actor_id: str, target_actor_id: str, relationship_id: str) -> ArchitectureEdge | None:
        for edge in self.graph.edges:
            if edge.source != source_actor_id or edge.relationship_id != relationship_id:
                continue
            if edge.target == target_actor_id:
                return edge
            if edge.dynamic and edge.target_selector and fnmatchcase(target_actor_id, edge.target_selector.id_pattern):
                return edge
        return None

    def boundary_for(self, edge: ArchitectureEdge) -> ArchitectureBoundary | None:
        return self.boundaries.get(edge.boundary_id) if edge.boundary_id else None


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
        findings.extend(self._lint_boundaries(graph))
        findings.extend(self._lint_orchestration(graph))
        findings.extend(self._delegation_cycles(graph))
        return tuple(findings)

    def _lint_boundaries(self, graph: ArchitectureGraph) -> list[ArchitectureFinding]:
        if not graph.trust_zones:
            return []
        findings: list[ArchitectureFinding] = []
        nodes = graph.node_map
        boundaries = {boundary.id: boundary for boundary in graph.boundaries}
        for node in graph.nodes:
            if node.trust_zone_id is None:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-NODE-ZONE-MISSING",
                        FindingSeverity.CRITICAL,
                        "every actor must belong to an explicit trust zone when zones are declared",
                        node_id=node.id,
                        remediation="Assign the actor to one trustZoneId before deployment.",
                    )
                )
        for edge in graph.edges:
            source_zone = nodes[edge.source].trust_zone_id
            target_zone = nodes[edge.target].trust_zone_id
            if source_zone is None or target_zone is None:
                continue
            crosses = source_zone != target_zone
            if crosses and edge.boundary_id is None:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-BOUNDARY-MISSING",
                        FindingSeverity.CRITICAL,
                        f"edge crosses {source_zone} -> {target_zone} without a trust boundary",
                        edge_id=edge.id,
                        remediation="Create a directional trust boundary and bind it with boundaryId.",
                    )
                )
                continue
            if not crosses and edge.boundary_id is not None:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-BOUNDARY-UNNECESSARY",
                        FindingSeverity.WARNING,
                        "edge references a trust boundary but both actors are in the same zone",
                        edge_id=edge.id,
                    )
                )
                continue
            if not crosses:
                continue
            boundary = boundaries[edge.boundary_id or ""]
            if (boundary.source_zone_id, boundary.target_zone_id) != (source_zone, target_zone):
                findings.append(
                    ArchitectureFinding(
                        "ARCH-BOUNDARY-DIRECTION-MISMATCH",
                        FindingSeverity.CRITICAL,
                        "edge direction does not match the referenced trust boundary",
                        edge_id=edge.id,
                    )
                )
            if edge.relationship not in boundary.allowed_relationships:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-BOUNDARY-RELATIONSHIP-DENIED",
                        FindingSeverity.CRITICAL,
                        f"boundary does not allow relationship {edge.relationship}",
                        edge_id=edge.id,
                    )
                )
            unexpected = edge.policy.allowed_data_classes - boundary.allowed_data_classes
            denied = edge.policy.allowed_data_classes & boundary.denied_data_classes
            if unexpected or denied:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-BOUNDARY-DATA-CLASS-DENIED",
                        FindingSeverity.CRITICAL,
                        "edge policy allows data classes outside the trust-boundary contract",
                        edge_id=edge.id,
                    )
                )
            required = self._required_points.get(edge.relationship_id)
            if required is not None and boundary.enforcement_point != required:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-BOUNDARY-ENFORCEMENT-MISMATCH",
                        FindingSeverity.CRITICAL,
                        f"{edge.relationship_id} boundary must be enforced at {required.value}",
                        edge_id=edge.id,
                    )
                )
            if boundary.mode == PolicyMode.OBSERVE:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-BOUNDARY-OBSERVE-ONLY",
                        FindingSeverity.HIGH,
                        "a trust-zone crossing is configured as observe-only",
                        edge_id=edge.id,
                    )
                )
            if boundary.failure_mode == FailureMode.FAIL_OPEN:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-BOUNDARY-FAIL-OPEN",
                        FindingSeverity.CRITICAL,
                        "a trust-zone boundary cannot fail open",
                        edge_id=edge.id,
                    )
                )
            if edge.relationship_id == "REL-06" and not (
                boundary.require_identity and boundary.require_tenant_binding
            ):
                findings.append(
                    ArchitectureFinding(
                        "ARCH-A2A-BOUNDARY-BINDING-WEAK",
                        FindingSeverity.CRITICAL,
                        "A2A trust-boundary crossing must bind identity and tenant",
                        edge_id=edge.id,
                    )
                )
        return findings

    def _lint_orchestration(self, graph: ArchitectureGraph) -> list[ArchitectureFinding]:
        definition = graph.orchestration
        if definition is None:
            return []
        findings: list[ArchitectureFinding] = []
        nodes = graph.node_map
        coordinator = nodes[definition.coordinator_actor_id].actor
        if coordinator.type not in {ActorType.AGENT, ActorType.SUBAGENT, ActorType.SCHEDULER}:
            findings.append(
                ArchitectureFinding(
                    "ARCH-ORCHESTRATOR-TYPE",
                    FindingSeverity.CRITICAL,
                    "orchestration coordinator must be an Agent, Sub-Agent, or Scheduler",
                    node_id=coordinator.id,
                )
            )
        for task in definition.tasks:
            expected_relationship = {
                TaskTransport.A2A: "REL-06",
                TaskTransport.MCP: "REL-05",
            }.get(task.transport)
            edge = (
                next(
                    (
                        candidate
                        for candidate in graph.edges
                        if candidate.source == task.source_actor_id
                        and candidate.target == task.target_actor_id
                        and candidate.relationship_id == expected_relationship
                    ),
                    None,
                )
                if expected_relationship
                else None
            )
            if expected_relationship and edge is None:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-TASK-TRANSPORT-EDGE-MISSING",
                        FindingSeverity.CRITICAL,
                        f"task {task.id} requires a declared {expected_relationship} edge",
                        node_id=task.target_actor_id,
                    )
                )
            if edge and task.data_classes - edge.policy.allowed_data_classes:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-TASK-DATA-CLASS-DENIED",
                        FindingSeverity.CRITICAL,
                        f"task {task.id} uses data classes outside its edge policy",
                        node_id=task.target_actor_id,
                    )
                )
            if not task.acceptance_criteria:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-TASK-ACCEPTANCE-MISSING",
                        FindingSeverity.WARNING,
                        f"task {task.id} has no explicit acceptance criteria",
                        node_id=task.target_actor_id,
                    )
                )
            high_risk = nodes[task.target_actor_id].actor.side_effects & {
                SideEffect.EXTERNAL_WRITE,
                SideEffect.DESTRUCTIVE_WRITE,
                SideEffect.PAYMENT,
                SideEffect.PERMISSION_CHANGE,
            }
            if high_risk and not task.approval_required:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-TASK-APPROVAL-MISSING",
                        FindingSeverity.CRITICAL,
                        f"high-risk task {task.id} requires an approval gate",
                        node_id=task.target_actor_id,
                    )
                )
        return findings

    def _lint_edge(self, edge: ArchitectureEdge, nodes: Mapping[str, ArchitectureNode]) -> list[ArchitectureFinding]:
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
                    remediation=("Attach a control with an explicit enforcement point and assurance level."),
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
            control.enforcement_point == required and control.assurance in acceptable_assurance
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
                        remediation=("Connect the declared control to an enforcement or observation adapter."),
                    )
                )
            if control.objective == SecurityObjective.PREVENT and control.timing == ControlTiming.POST_EXECUTION:
                findings.append(
                    ArchitectureFinding(
                        "ARCH-PREVENT-AFTER-EXECUTION",
                        FindingSeverity.CRITICAL,
                        f"control {control.id} cannot prevent an action after execution",
                        edge_id=edge.id,
                        remediation=("Move it to PRE_EXECUTION or change the objective to DETECT/RESPOND."),
                    )
                )

        if "D5" in edge.policy.allowed_data_classes:
            findings.append(
                ArchitectureFinding(
                    "ARCH-CREDENTIAL-DATA-ALLOWED",
                    FindingSeverity.CRITICAL,
                    "credential data class D5 is allowed across the relationship",
                    edge_id=edge.id,
                    remediation=("Deny D5 and use opaque credential references with a credential broker."),
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
                edge.policy.require_actor_binding and edge.policy.require_audience and edge.policy.require_resource
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
                        remediation=("Break the cycle or require a strict decreasing delegation budget."),
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
        boundaries = {boundary.id: boundary for boundary in graph.boundaries}
        return CompiledArchitecture(
            graph=graph,
            actors=actors,
            links=links,
            boundaries=boundaries,
            findings=findings,
        )


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
        event.interaction_id for event in event_list if event.event_type == "CONTROL_EVALUATED" and event.interaction_id
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
        return bool(edge.target_selector and fnmatchcase(item.target, edge.target_selector.id_pattern))

    undeclared = tuple(item for item in observed if not any(matches(edge, item) for edge in graph.edges))
    unobserved = tuple(edge.id for edge in graph.edges if not any(matches(edge, item) for item in observed))
    evaluated = set(control_evaluated_interactions)
    bypass = tuple(
        dict.fromkeys(
            item.interaction_id for item in observed if item.interaction_id and item.interaction_id not in evaluated
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
            side_effects=frozenset(SideEffect(value) for value in _strings(item.get("sideEffects", []), "sideEffects")),
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
        trust_zone=TrustZone(str(item["trustZone"])) if item.get("trustZone") is not None else None,
        trust_zone_id=str(item["trustZoneId"]) if item.get("trustZoneId") is not None else None,
    )


def _parse_trust_zone(value: Any) -> ArchitectureTrustZone:
    item = _mapping(value, "trust zone")
    bounds = _mapping(item.get("bounds"), "trust zone bounds")
    return ArchitectureTrustZone(
        id=_required_string(item, "id"),
        label=_required_string(item, "label"),
        kind=TrustZone(_required_string(item, "kind")),
        description=str(item.get("description", "")),
        bounds=(
            float(bounds.get("x", 0)),
            float(bounds.get("y", 0)),
            float(bounds.get("width", 0)),
            float(bounds.get("height", 0)),
        ),
    )


def _parse_boundary(value: Any) -> ArchitectureBoundary:
    item = _mapping(value, "trust boundary")
    return ArchitectureBoundary(
        id=_required_string(item, "id"),
        label=_required_string(item, "label"),
        source_zone_id=_required_string(item, "sourceZoneId"),
        target_zone_id=_required_string(item, "targetZoneId"),
        enforcement_point=EnforcementPoint(_required_string(item, "enforcementPoint")),
        allowed_relationships=frozenset(
            _strings(item.get("allowedRelationships", []), "allowedRelationships")
        ),
        allowed_data_classes=frozenset(
            _strings(item.get("allowedDataClasses", ["D2", "D3", "D7"]), "allowedDataClasses")
        ),
        denied_data_classes=frozenset(
            _strings(item.get("deniedDataClasses", ["D5", "D8"]), "deniedDataClasses")
        ),
        mode=PolicyMode(str(item.get("mode", "ENFORCE"))),
        failure_mode=FailureMode(str(item.get("failureMode", "FAIL_CLOSED"))),
        require_identity=bool(item.get("requireIdentity", True)),
        require_tenant_binding=bool(item.get("requireTenantBinding", True)),
        max_payload_bytes=int(item.get("maxPayloadBytes", 1_048_576)),
        description=str(item.get("description", "")),
    )


def _parse_orchestration(value: Any) -> OrchestrationDefinition:
    item = _mapping(value, "orchestration")
    policy_value = _mapping(item.get("runPolicy", {}), "orchestration.runPolicy")
    return OrchestrationDefinition(
        coordinator_actor_id=_required_string(item, "coordinatorActorId"),
        pattern=OrchestrationPattern(_required_string(item, "pattern")),
        tasks=tuple(
            _parse_orchestration_task(task)
            for task in _sequence(item.get("tasks", []), "orchestration.tasks")
        ),
        run_policy=OrchestrationRunPolicy(
            max_parallelism=int(policy_value.get("maxParallelism", 4)),
            max_tasks=int(policy_value.get("maxTasks", 100)),
            max_duration_seconds=int(policy_value.get("maxDurationSeconds", 3600)),
            max_messages=int(policy_value.get("maxMessages", 500)),
            fail_fast=bool(policy_value.get("failFast", True)),
        ),
    )


def _parse_orchestration_task(value: Any) -> OrchestrationTask:
    item = _mapping(value, "orchestration task")
    position_value = item.get("position")
    position = None
    if position_value is not None:
        position_map = _mapping(position_value, "orchestration task position")
        position = (float(position_map.get("x", 0)), float(position_map.get("y", 0)))
    return OrchestrationTask(
        id=_required_string(item, "id"),
        label=_required_string(item, "label"),
        source_actor_id=_required_string(item, "sourceActorId"),
        target_actor_id=_required_string(item, "targetActorId"),
        transport=TaskTransport(_required_string(item, "transport")),
        purpose=_required_string(item, "purpose"),
        depends_on=_strings(item.get("dependsOn", []), "dependsOn"),
        data_classes=frozenset(_strings(item.get("dataClasses", ["D3"]), "dataClasses")),
        acceptance_criteria=_strings(item.get("acceptanceCriteria", []), "acceptanceCriteria"),
        max_attempts=int(item.get("maxAttempts", 1)),
        timeout_seconds=int(item.get("timeoutSeconds", 300)),
        approval_required=bool(item.get("approvalRequired", False)),
        on_failure=TaskFailureAction(str(item.get("onFailure", "FAIL_WORKFLOW"))),
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
        external_write_requires_approval=bool(policy_value.get("externalWriteRequiresApproval", True)),
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
                ActorType(value) for value in _strings(selector_map.get("types", []), "targetSelector.types")
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
        boundary_id=str(item["boundaryId"]) if item.get("boundaryId") is not None else None,
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


def _boundary_value(boundary: ArchitectureBoundary) -> dict[str, Any]:
    return {
        "id": boundary.id,
        "label": boundary.label,
        "sourceZoneId": boundary.source_zone_id,
        "targetZoneId": boundary.target_zone_id,
        "enforcementPoint": boundary.enforcement_point.value,
        "allowedRelationships": sorted(boundary.allowed_relationships),
        "allowedDataClasses": sorted(boundary.allowed_data_classes),
        "deniedDataClasses": sorted(boundary.denied_data_classes),
        "mode": boundary.mode.value,
        "failureMode": boundary.failure_mode.value,
        "requireIdentity": boundary.require_identity,
        "requireTenantBinding": boundary.require_tenant_binding,
        "maxPayloadBytes": boundary.max_payload_bytes,
        "description": boundary.description,
    }


def _orchestration_value(definition: OrchestrationDefinition) -> dict[str, Any]:
    return {
        "coordinatorActorId": definition.coordinator_actor_id,
        "pattern": definition.pattern.value,
        "runPolicy": {
            "maxParallelism": definition.run_policy.max_parallelism,
            "maxTasks": definition.run_policy.max_tasks,
            "maxDurationSeconds": definition.run_policy.max_duration_seconds,
            "maxMessages": definition.run_policy.max_messages,
            "failFast": definition.run_policy.fail_fast,
        },
        "tasks": [
            {
                "id": task.id,
                "label": task.label,
                "sourceActorId": task.source_actor_id,
                "targetActorId": task.target_actor_id,
                "transport": task.transport.value,
                "purpose": task.purpose,
                "dependsOn": list(task.depends_on),
                "dataClasses": sorted(task.data_classes),
                "acceptanceCriteria": list(task.acceptance_criteria),
                "maxAttempts": task.max_attempts,
                "timeoutSeconds": task.timeout_seconds,
                "approvalRequired": task.approval_required,
                "onFailure": task.on_failure.value,
                **(
                    {"position": {"x": task.position[0], "y": task.position[1]}}
                    if task.position is not None
                    else {}
                ),
            }
            for task in definition.tasks
        ],
    }


def _validate_acyclic_tasks(tasks: Iterable[OrchestrationTask]) -> None:
    dependencies = {task.id: task.depends_on for task in tasks}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise ValueError(f"orchestration task dependency cycle detected at {task_id}")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dependency in dependencies.get(task_id, ()):
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in dependencies:
        visit(task_id)


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
