"""Command line entry point for architecture validation and compilation."""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from .architecture import (
    ArchitectureCompiler,
    ArchitectureGraph,
    FindingSeverity,
    compare_observed_runtime,
)
from .canonical import canonical_digest
from .models import PolicyMode
from .telemetry import import_runtime_telemetry


def _load(path: str) -> ArchitectureGraph:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return ArchitectureGraph.from_dict(value)


def _finding_value(finding) -> dict[str, str | None]:
    return {
        "code": finding.code,
        "severity": finding.severity.value,
        "message": finding.message,
        "nodeId": finding.node_id,
        "edgeId": finding.edge_id,
        "remediation": finding.remediation,
    }


def _compile_shadow(graph, compiler, findings) -> int:  # noqa: ANN001
    """Review gate + SHADOW deploy: block on critical findings, else emit a SHADOW bundle."""
    if any(item.severity == FindingSeverity.CRITICAL for item in findings):
        print(
            json.dumps(
                {
                    "architectureId": graph.id,
                    "version": graph.version,
                    "mode": "SHADOW",
                    "deployable": False,
                    "findings": [_finding_value(item) for item in findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2
    compiled = compiler.compile(graph, reject_critical=False)
    links = [
        {
            "edgeId": edge.id,
            "policyId": replace(compiled.links[edge.id], mode=PolicyMode.SHADOW).id,
            "source": edge.source,
            "target": edge.target,
            "relationship": edge.relationship,
            "mode": PolicyMode.SHADOW.value,
        }
        for edge in graph.edges
    ]
    body = {
        "architectureId": graph.id,
        "version": graph.version,
        "actors": sorted(compiled.actors),
        "links": links,
    }
    print(
        json.dumps(
            {
                **body,
                "mode": "SHADOW",
                "deployable": True,
                "bundleDigest": canonical_digest(body),
                "findings": [_finding_value(item) for item in findings],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="interlock")
    commands = parser.add_subparsers(dest="command", required=True)
    architecture = commands.add_parser("architecture", help="work with Architecture manifests")
    actions = architecture.add_subparsers(dest="action", required=True)
    for name in ("lint", "graph"):
        command = actions.add_parser(name)
        command.add_argument("manifest")
    compile_command = actions.add_parser("compile")
    compile_command.add_argument("manifest")
    compile_command.add_argument(
        "--shadow",
        action="store_true",
        help="gate on critical findings, force every edge to SHADOW, and emit a deployable bundle",
    )
    runtime_diff = actions.add_parser("runtime-diff")
    runtime_diff.add_argument("manifest")
    runtime_diff.add_argument("telemetry")
    args = parser.parse_args(argv)

    graph = _load(args.manifest)
    compiler = ArchitectureCompiler()
    findings = compiler.linter.lint(graph)
    if args.action == "runtime-diff":
        telemetry_value = json.loads(Path(args.telemetry).read_text(encoding="utf-8"))
        imported = import_runtime_telemetry(telemetry_value)
        diff = compare_observed_runtime(
            graph,
            imported.observations,
            imported.control_evaluated_interactions,
        )
        print(
            json.dumps(
                {
                    "architectureId": graph.id,
                    "format": imported.format,
                    "conforms": diff.conforms,
                    "observedRelationships": len(imported.observations),
                    "undeclaredRelationships": [
                        {
                            "source": item.source,
                            "target": item.target,
                            "relationship": item.relationship,
                            "relationshipId": item.relationship_id,
                            "interactionId": item.interaction_id,
                        }
                        for item in diff.undeclared_edges
                    ],
                    "unobservedEdgeIds": list(diff.unobserved_edge_ids),
                    "controlBypassInteractions": list(diff.control_bypass_interactions),
                    "importIssues": [
                        {"code": item.code, "message": item.message, "spanId": item.span_id}
                        for item in imported.issues
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if diff.conforms and not imported.issues else 3
    if args.action == "lint":
        print(
            json.dumps(
                {
                    "architectureId": graph.id,
                    "version": graph.version,
                    "valid": not any(
                        item.severity == FindingSeverity.CRITICAL for item in findings
                    ),
                    "findings": [_finding_value(item) for item in findings],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2 if any(item.severity == FindingSeverity.CRITICAL for item in findings) else 0
    if args.action == "graph":
        print(json.dumps(graph.to_design_graph(), ensure_ascii=False, indent=2))
        return 0

    if getattr(args, "shadow", False):
        return _compile_shadow(graph, compiler, findings)

    compiled = compiler.compile(graph)
    print(
        json.dumps(
            {
                "architectureId": graph.id,
                "version": graph.version,
                "actors": sorted(compiled.actors),
                "links": [
                    {
                        "edgeId": edge.id,
                        "policyId": compiled.links[edge.id].id,
                        "source": edge.source,
                        "target": edge.target,
                        "relationship": edge.relationship,
                        "mode": compiled.links[edge.id].mode.value,
                    }
                    for edge in graph.edges
                ],
                "findings": [_finding_value(item) for item in compiled.findings],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
