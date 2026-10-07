"""Studio deployment workflow: git-backed bundle review, two-person promote, rollback.

The ``interlock architecture compile --shadow`` bundle is the reviewable unit.
This module stores bundles in a local git repository, gates the SHADOW→ENFORCE
promotion behind two distinct signed approvals over the exact bundle digest
(the same two-person rule the config guard uses), and supports rollback to any
previously active bundle digest. Real git is the transport; a hosted Git host /
PR review is the same workflow at the remote boundary.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .architecture import ArchitectureCompiler, ArchitectureGraph, FindingSeverity
from .canonical import canonical_digest
from .models import PolicyMode
from .signing import sign_canonical_ed25519, verify_canonical_ed25519

REASON_TWO_PERSON_REQUIRED = "L1-STUDIO-TWO-PERSON-APPROVAL-REQUIRED"
REASON_SIGNATURE_INVALID = "L1-STUDIO-APPROVAL-SIGNATURE-INVALID"
REASON_BUNDLE_UNKNOWN = "L1-STUDIO-BUNDLE-UNKNOWN"
REASON_DIGEST_MISMATCH = "L1-STUDIO-BUNDLE-DIGEST-MISMATCH"
REASON_ROLLBACK_TARGET_NOT_ACTIVE = "L1-STUDIO-ROLLBACK-TARGET-NOT-ACTIVE"


class StudioDeploymentError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class DeploymentApproval:
    approver_id: str
    key_id: str
    signature: str


@dataclass(frozen=True, slots=True)
class TrustedApprovalKey:
    """One approver identity bound to one Ed25519 verification key."""

    approver_id: str
    public_key: bytes

    def __post_init__(self) -> None:
        if not self.approver_id or len(self.public_key) != 32:
            raise ValueError("trusted approver requires an identity and a 32-byte Ed25519 public key")


@dataclass(frozen=True, slots=True)
class DeploymentBundle:
    architecture_id: str
    version: str
    bundle_digest: str
    body: Mapping[str, Any]

    @classmethod
    def from_compile_output(cls, value: Mapping[str, Any]) -> DeploymentBundle:
        if not value.get("deployable", False):
            raise StudioDeploymentError(REASON_BUNDLE_UNKNOWN, "compile output is not a deployable bundle")
        body = {
            "architectureId": value["architectureId"],
            "version": value["version"],
            "actors": value["actors"],
            "links": value["links"],
            **({"architecture": value["architecture"]} if "architecture" in value else {}),
        }
        recomputed = canonical_digest(body)
        if recomputed != value.get("bundleDigest"):
            raise StudioDeploymentError(REASON_DIGEST_MISMATCH, "bundle digest does not match its body")
        return cls(value["architectureId"], str(value["version"]), recomputed, body)


def compile_review_bundle(graph: ArchitectureGraph) -> dict[str, Any]:
    """One review compiler shared by the CLI and Studio HTTP endpoint."""
    from .configurable_runtime import prepare_runtime_graph

    graph = prepare_runtime_graph(graph)
    compiler = ArchitectureCompiler()
    findings = compiler.linter.lint(graph)
    report = [
        {
            "code": item.code,
            "severity": item.severity.value,
            "message": item.message,
            "nodeId": item.node_id,
            "edgeId": item.edge_id,
            "remediation": item.remediation,
        }
        for item in findings
    ]
    if any(item.severity == FindingSeverity.CRITICAL for item in findings):
        return {
            "architectureId": graph.id,
            "version": graph.version,
            "mode": "SHADOW",
            "deployable": False,
            "findings": report,
        }
    graph = replace(
        graph, edges=tuple(replace(edge, policy=replace(edge.policy, mode=PolicyMode.SHADOW)) for edge in graph.edges)
    )
    compiled = compiler.compile(graph, reject_critical=False)
    body = {
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
        "architecture": graph.to_manifest(),
    }
    return {**body, "mode": "SHADOW", "deployable": True, "bundleDigest": canonical_digest(body), "findings": report}


def deployed_architecture(bundle_body: Mapping[str, Any], mode: str) -> ArchitectureGraph:
    """Parse a bundle's architecture and apply the deployment record's mode to every edge.

    The source of truth for a deployed run is the deployment record, not the
    per-edge modes baked into the reviewed bundle (D5). Every caller that
    loads an active bundle for execution must go through this helper so the
    applied mode always matches the record.
    """
    architecture = bundle_body.get("architecture")
    if not isinstance(architecture, Mapping):
        raise StudioDeploymentError(REASON_BUNDLE_UNKNOWN, "bundle does not contain an executable architecture")
    graph = ArchitectureGraph.from_dict(architecture)
    applied_mode = PolicyMode(mode)
    return replace(
        graph,
        edges=tuple(replace(edge, policy=replace(edge.policy, mode=applied_mode)) for edge in graph.edges),
        boundaries=tuple(replace(boundary, mode=applied_mode) for boundary in graph.boundaries),
    )


def deployment_approval_statement(
    bundle: DeploymentBundle, *, from_digest: str | None, to_mode: str, target_id: str, tenant_id: str,
) -> dict[str, Any]:
    """The exact deployment target, tenant, bundle, base and mode each approver signs."""
    if (not isinstance(target_id, str) or not target_id.strip()
            or not isinstance(tenant_id, str) or not tenant_id.strip()):
        raise ValueError("deployment approvals require target_id and tenant_id")
    return {
        "purpose": "studio-architecture-deploy",
        "targetId": target_id,
        "tenantId": tenant_id,
        "architectureId": bundle.architecture_id,
        "bundleDigest": bundle.bundle_digest,
        "fromDigest": from_digest,
        "toMode": to_mode,
    }


def approval_signature_statement(
    bundle: DeploymentBundle,
    *,
    from_digest: str | None,
    to_mode: str,
    target_id: str,
    tenant_id: str,
    approver_id: str,
    key_id: str,
) -> dict[str, Any]:
    """Return the full signed value, including the asserted approver identity."""
    return {
        **deployment_approval_statement(
            bundle, from_digest=from_digest, to_mode=to_mode, target_id=target_id, tenant_id=tenant_id,
        ),
        "approverId": approver_id,
        "keyId": key_id,
    }


def sign_deployment_approval(
    bundle: DeploymentBundle,
    *,
    from_digest: str | None,
    to_mode: str,
    target_id: str,
    tenant_id: str,
    approver_id: str,
    key_id: str,
    key: bytes,
) -> DeploymentApproval:
    signed = approval_signature_statement(
        bundle,
        from_digest=from_digest,
        to_mode=to_mode,
        target_id=target_id,
        tenant_id=tenant_id,
        approver_id=approver_id,
        key_id=key_id,
    )
    return DeploymentApproval(approver_id, key_id, sign_canonical_ed25519(signed, key))


def _verify_two_person(
    statement: Mapping[str, Any],
    approvals: tuple[DeploymentApproval, ...],
    trusted_approvers: Mapping[str, TrustedApprovalKey],
) -> None:
    approvers: set[str] = set()
    keys: set[bytes] = set()
    for approval in approvals:
        verify_deployment_approval(statement, approval, trusted_approvers)
        approvers.add(approval.approver_id)
        keys.add(trusted_approvers[approval.key_id].public_key)
    if len(approvers) < 2 or len(keys) < 2:
        raise StudioDeploymentError(REASON_TWO_PERSON_REQUIRED, "promotion requires two distinct signed approvals")


def verify_deployment_approval(
    statement: Mapping[str, Any],
    approval: DeploymentApproval,
    trusted_approvers: Mapping[str, TrustedApprovalKey],
) -> None:
    """Verify one approval against its configured identity and public key."""
    trusted = trusted_approvers.get(approval.key_id)
    signed = {**statement, "approverId": approval.approver_id, "keyId": approval.key_id}
    if (
        any(not isinstance(statement.get(key), str) or not statement[key].strip() for key in ("targetId", "tenantId"))
        or trusted is None
        or trusted.approver_id != approval.approver_id
        or not verify_canonical_ed25519(signed, approval.signature, trusted.public_key)
    ):
        raise StudioDeploymentError(REASON_SIGNATURE_INVALID, "approval signature is invalid")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _write_json(path: Path, value: Any, *, exclusive: bool = False) -> None:
    """Replace one durable JSON record without exposing a partial write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class GitBundleStore:
    """Local git repository holding reviewable bundles and the active pointer.

    Layout: ``deploy/bundles/<digest>.json`` (immutable bundle records) and
    ``deploy/active.json`` (the promoted bundle + its enforced mode). Every
    operation is a commit, so ``git log`` is the deployment audit trail.
    """

    def __init__(
        self, repo: str | Path, *, author: str = "interlock-studio", tenant_id: str | None = None,
    ) -> None:
        self.repo = Path(repo)
        self._author = author
        if not (self.repo / ".git").exists():
            self.repo.mkdir(parents=True, exist_ok=True)
            _git(self.repo, "init", "-q", "-b", "main")
            _git(self.repo, "config", "user.email", "studio@interlock.local")
            _git(self.repo, "config", "user.name", author)
        (self.repo / "deploy" / "bundles").mkdir(parents=True, exist_ok=True)
        target_path = self.repo / "deploy" / "target.json"
        if target_path.exists():
            target = json.loads(target_path.read_text(encoding="utf-8"))
        else:
            target = {"targetId": str(uuid.uuid4()), "tenantId": tenant_id if tenant_id is not None else "tenant-local"}
            self._validate_target(target)
            try:
                _write_json(target_path, target, exclusive=True)
            except FileExistsError:
                target = json.loads(target_path.read_text(encoding="utf-8"))
        self._validate_target(target)
        if tenant_id is not None and tenant_id != target["tenantId"]:
            raise ValueError("deployment store belongs to a different tenant")
        self.target_id = target["targetId"]
        self.tenant_id = target["tenantId"]

    @staticmethod
    def _validate_target(target: Any) -> None:
        if (not isinstance(target, dict) or set(target) != {"targetId", "tenantId"}
                or not isinstance(target["targetId"], str) or not target["targetId"].strip()
                or not isinstance(target["tenantId"], str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", target["tenantId"])):
            raise ValueError("deployment target requires targetId and a valid tenantId")

    def approval_statement(
        self, bundle: DeploymentBundle, *, from_digest: str | None, to_mode: str = "ENFORCE",
    ) -> dict[str, Any]:
        return deployment_approval_statement(
            bundle, from_digest=from_digest, to_mode=to_mode, target_id=self.target_id, tenant_id=self.tenant_id,
        )

    def _commit(self, message: str) -> str:
        _git(self.repo, "add", "-A", "--", "deploy")
        _git(self.repo, "commit", "-q", "-m", message, "--", "deploy")
        return _git(self.repo, "rev-parse", "HEAD")

    def propose(self, bundle: DeploymentBundle) -> str:
        """Write the SHADOW bundle as an immutable record and commit it."""
        path = self.repo / "deploy" / "bundles" / f"{bundle.bundle_digest}.json"
        if path.exists():
            self._load_bundle(bundle.bundle_digest)
            return _git(self.repo, "rev-parse", "HEAD")
        record = {"mode": "SHADOW", "bundleDigest": bundle.bundle_digest, "body": bundle.body}
        _write_json(path, record)
        return self._commit(f"studio: propose {bundle.bundle_digest} (SHADOW)")

    def _load_bundle(self, bundle_digest: str) -> DeploymentBundle:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", bundle_digest):
            raise StudioDeploymentError(REASON_BUNDLE_UNKNOWN, "invalid bundle digest")
        path = self.repo / "deploy" / "bundles" / f"{bundle_digest}.json"
        if not path.exists():
            raise StudioDeploymentError(REASON_BUNDLE_UNKNOWN, "bundle is not in the review store")
        record = json.loads(path.read_text(encoding="utf-8"))
        body = record["body"]
        if canonical_digest(body) != bundle_digest:
            raise StudioDeploymentError(REASON_DIGEST_MISMATCH, "stored bundle digest does not match its body")
        return DeploymentBundle(body["architectureId"], str(body["version"]), bundle_digest, body)

    def bundle(self, bundle_digest: str) -> DeploymentBundle:
        """Load and integrity-check a proposed bundle."""
        return self._load_bundle(bundle_digest)

    def active(self) -> dict[str, Any] | None:
        path = self.repo / "deploy" / "active.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def approval_path(self) -> Path:
        path = Path(_git(self.repo, "rev-parse", "--git-path", "interlock-pending-approvals.json"))
        return path if path.is_absolute() else self.repo / path

    def diff(self, bundle_digest: str) -> dict[str, Any]:
        """Review the complete candidate architecture against the current deployment."""
        candidate = self.bundle(bundle_digest)
        active = self.active()
        base_digest = active["bundleDigest"] if active else None
        before = self.bundle(base_digest).body if base_digest else {}
        changes: list[dict[str, Any]] = []
        missing = object()

        def visit(old: Any, new: Any, path: str) -> None:
            if old is missing or new is missing:
                changes.append({"path": path or "/", "op": "add" if old is missing else "remove",
                                "before": None if old is missing else old, "after": None if new is missing else new})
                return
            if old == new:
                return
            if isinstance(old, Mapping) and isinstance(new, Mapping):
                for key in sorted(set(old) | set(new)):
                    segment = str(key).replace("~", "~0").replace("/", "~1")
                    visit(old.get(key, missing), new.get(key, missing), f"{path}/{segment}")
            elif (
                isinstance(old, list)
                and isinstance(new, list)
                and all(isinstance(item, Mapping) and isinstance(item.get("id"), str) for item in old + new)
            ):
                visit({item["id"]: item for item in old}, {item["id"]: item for item in new}, path)
            else:
                changes.append({"path": path or "/", "op": "replace", "before": old, "after": new})

        visit(before.get("architecture", before), candidate.body.get("architecture", candidate.body), "")
        return {
            "baseDigest": base_digest,
            "bundleDigest": bundle_digest,
            "changes": changes,
            "changeCount": len(changes),
        }

    def promote(
        self,
        bundle_digest: str,
        approvals: tuple[DeploymentApproval, ...],
        *,
        trusted_approvers: Mapping[str, TrustedApprovalKey],
    ) -> str:
        """Two-person-gated SHADOW→ENFORCE promotion of a proposed bundle."""
        bundle = self._load_bundle(bundle_digest)
        current = self.active()
        from_digest = current["bundleDigest"] if current else None
        statement = self.approval_statement(bundle, from_digest=from_digest)
        _verify_two_person(statement, approvals, trusted_approvers)
        active = {
            "mode": "ENFORCE",
            "bundleDigest": bundle_digest,
            "promotedFrom": from_digest,
            "approvers": sorted({approval.approver_id for approval in approvals}),
        }
        _write_json(self.repo / "deploy" / "active.json", active)
        activation = self.repo / "deploy" / "activations" / f"{bundle_digest}.json"
        activation.parent.mkdir(parents=True, exist_ok=True)
        _write_json(activation, {"bundleDigest": bundle_digest, "approvers": active["approvers"]})
        return self._commit(f"studio: promote {bundle_digest} SHADOW->ENFORCE")

    def rollback(
        self,
        target_digest: str,
        approvals: tuple[DeploymentApproval, ...],
        *,
        trusted_approvers: Mapping[str, TrustedApprovalKey],
    ) -> str:
        """Restore a previously active bundle after a fresh two-person approval."""
        bundle = self._load_bundle(target_digest)
        current = self.active()
        activation = self.repo / "deploy" / "activations" / f"{target_digest}.json"
        if not activation.exists() and (current is None or current.get("bundleDigest") != target_digest):
            raise StudioDeploymentError(
                REASON_ROLLBACK_TARGET_NOT_ACTIVE,
                "rollback target has never been an active bundle",
            )
        from_digest = current["bundleDigest"] if current else None
        statement = self.approval_statement(bundle, from_digest=from_digest)
        _verify_two_person(statement, approvals, trusted_approvers)
        active = {
            "mode": "ENFORCE",
            "bundleDigest": target_digest,
            "rolledBackFrom": from_digest,
            "approvers": sorted({approval.approver_id for approval in approvals}),
        }
        _write_json(self.repo / "deploy" / "active.json", active)
        return self._commit(f"studio: rollback to {target_digest}")

    def history(self) -> tuple[str, ...]:
        try:
            _git(self.repo, "rev-parse", "--verify", "HEAD")
        except subprocess.CalledProcessError:
            return ()
        log = _git(self.repo, "log", "--format=%s")
        return tuple(line for line in log.splitlines() if line)
