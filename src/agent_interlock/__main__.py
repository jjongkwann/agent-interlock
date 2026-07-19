"""Command line entry point for architecture validation and compilation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from .architecture import ArchitectureCompiler, ArchitectureGraph, FindingSeverity, compare_observed_runtime
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


def _studio_main(args: argparse.Namespace) -> int:
    from .studio_deploy import (
        DeploymentApproval,
        DeploymentBundle,
        GitBundleStore,
        StudioDeploymentError,
        deployment_approval_statement,
        sign_deployment_approval,
    )

    def _emit(value: dict) -> int:
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0

    try:
        if args.action == "propose":
            bundle = DeploymentBundle.from_compile_output(json.loads(Path(args.bundle).read_text(encoding="utf-8")))
            commit = GitBundleStore(args.repo).propose(bundle)
            return _emit({"bundleDigest": bundle.bundle_digest, "commit": commit})
        if args.action == "approve":
            key_hex = os.environ.get(args.key_env, "")
            if not key_hex:
                print(f"approval key env {args.key_env} is empty", file=sys.stderr)
                return 2
            bundle = DeploymentBundle.from_compile_output(json.loads(Path(args.bundle).read_text(encoding="utf-8")))
            from_digest = args.from_digest
            if from_digest is None and args.repo:
                active = GitBundleStore(args.repo).active()
                from_digest = active["bundleDigest"] if active else None
            approval = sign_deployment_approval(
                bundle,
                from_digest=from_digest,
                to_mode="ENFORCE",
                approver_id=args.approver,
                key_id=args.key_id,
                key=bytes.fromhex(key_hex),
            )
            return _emit(
                {
                    "approverId": approval.approver_id,
                    "keyId": approval.key_id,
                    "signature": approval.signature,
                    "statement": deployment_approval_statement(bundle, from_digest=from_digest, to_mode="ENFORCE"),
                }
            )
        store = GitBundleStore(args.repo)
        if args.action == "promote":
            approvals = tuple(
                DeploymentApproval(item["approverId"], item["keyId"], item["signature"])
                for item in (json.loads(Path(path).read_text(encoding="utf-8")) for path in args.approval)
            )
            trusted = {
                key_id: bytes.fromhex(value)
                for key_id, value in json.loads(Path(args.trusted_keys).read_text(encoding="utf-8")).items()
            }
            commit = store.promote(args.digest, approvals, trusted_keys=trusted)
            return _emit({"active": store.active(), "commit": commit})
        if args.action == "rollback":
            commit = store.rollback(args.digest)
            return _emit({"active": store.active(), "commit": commit})
        return _emit({"active": store.active(), "history": list(store.history())})
    except StudioDeploymentError as error:
        print(
            json.dumps({"error": {"code": error.reason_code, "message": str(error)}}, indent=2),
            file=sys.stderr,
        )
        return 2


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
    skeleton_command = actions.add_parser("skeleton")
    skeleton_command.add_argument("manifest")
    skeleton_command.add_argument("--out-dir", default=".")

    studio = commands.add_parser("studio", help="bundle review, two-person promotion, rollback")
    studio_actions = studio.add_subparsers(dest="action", required=True)
    propose = studio_actions.add_parser("propose")
    propose.add_argument("bundle")
    propose.add_argument("--repo", required=True)
    approve = studio_actions.add_parser("approve")
    approve.add_argument("bundle")
    approve.add_argument("--repo")
    approve.add_argument("--from-digest")
    approve.add_argument("--approver", required=True)
    approve.add_argument("--key-id", required=True)
    approve.add_argument("--key-env", default="INTERLOCK_APPROVAL_KEY")
    promote = studio_actions.add_parser("promote")
    promote.add_argument("digest")
    promote.add_argument("--repo", required=True)
    promote.add_argument("--approval", action="append", required=True)
    promote.add_argument("--trusted-keys", required=True)
    rollback = studio_actions.add_parser("rollback")
    rollback.add_argument("digest")
    rollback.add_argument("--repo", required=True)
    status = studio_actions.add_parser("status")
    status.add_argument("--repo", required=True)

    args = parser.parse_args(argv)
    if args.command == "studio":
        return _studio_main(args)

    graph = _load(args.manifest)
    compiler = ArchitectureCompiler()
    findings = compiler.linter.lint(graph)
    if args.action == "skeleton":
        from .scaffold import generate_security_tests, generate_skeleton, python_identifier

        base = python_identifier(graph.id)
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        skeleton_path = out_dir / f"{base}_skeleton.py"
        tests_path = out_dir / f"test_{base}_security.py"
        skeleton_path.write_text(generate_skeleton(graph), encoding="utf-8")
        tests_path.write_text(generate_security_tests(graph, f"{base}_skeleton"), encoding="utf-8")
        print(
            json.dumps(
                {"architectureId": graph.id, "written": [str(skeleton_path), str(tests_path)]},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
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
                        {"code": item.code, "message": item.message, "spanId": item.span_id} for item in imported.issues
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
                    "valid": not any(item.severity == FindingSeverity.CRITICAL for item in findings),
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
