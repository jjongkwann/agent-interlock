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
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical import canonical_digest
from .signing import sign_canonical, verify_canonical

REASON_TWO_PERSON_REQUIRED = "L1-STUDIO-TWO-PERSON-APPROVAL-REQUIRED"
REASON_SIGNATURE_INVALID = "L1-STUDIO-APPROVAL-SIGNATURE-INVALID"
REASON_BUNDLE_UNKNOWN = "L1-STUDIO-BUNDLE-UNKNOWN"
REASON_DIGEST_MISMATCH = "L1-STUDIO-BUNDLE-DIGEST-MISMATCH"


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
class DeploymentBundle:
    architecture_id: str
    version: str
    bundle_digest: str
    body: Mapping[str, Any]

    @classmethod
    def from_compile_output(cls, value: Mapping[str, Any]) -> "DeploymentBundle":
        if not value.get("deployable", False):
            raise StudioDeploymentError(REASON_BUNDLE_UNKNOWN, "compile output is not a deployable bundle")
        body = {
            "architectureId": value["architectureId"],
            "version": value["version"],
            "actors": value["actors"],
            "links": value["links"],
        }
        recomputed = canonical_digest(body)
        if recomputed != value.get("bundleDigest"):
            raise StudioDeploymentError(REASON_DIGEST_MISMATCH, "bundle digest does not match its body")
        return cls(value["architectureId"], str(value["version"]), recomputed, body)


def deployment_approval_statement(
    bundle: DeploymentBundle, *, from_digest: str | None, to_mode: str
) -> dict[str, Any]:
    """The exact context each approver signs: bundle identity, base, and target mode."""
    return {
        "purpose": "studio-architecture-deploy",
        "architectureId": bundle.architecture_id,
        "bundleDigest": bundle.bundle_digest,
        "fromDigest": from_digest,
        "toMode": to_mode,
    }


def sign_deployment_approval(
    bundle: DeploymentBundle,
    *,
    from_digest: str | None,
    to_mode: str,
    approver_id: str,
    key_id: str,
    key: bytes,
) -> DeploymentApproval:
    statement = deployment_approval_statement(bundle, from_digest=from_digest, to_mode=to_mode)
    return DeploymentApproval(approver_id, key_id, sign_canonical(statement, key))


def _verify_two_person(
    statement: Mapping[str, Any],
    approvals: tuple[DeploymentApproval, ...],
    trusted_keys: Mapping[str, bytes],
) -> None:
    approvers: set[str] = set()
    keys: set[str] = set()
    for approval in approvals:
        key = trusted_keys.get(approval.key_id)
        if not key or not verify_canonical(statement, approval.signature, key):
            raise StudioDeploymentError(REASON_SIGNATURE_INVALID, "approval signature is invalid")
        approvers.add(approval.approver_id)
        keys.add(approval.key_id)
    if len(approvers) < 2 or len(keys) < 2:
        raise StudioDeploymentError(
            REASON_TWO_PERSON_REQUIRED, "promotion requires two distinct signed approvals"
        )


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


class GitBundleStore:
    """Local git repository holding reviewable bundles and the active pointer.

    Layout: ``deploy/bundles/<digest>.json`` (immutable bundle records) and
    ``deploy/active.json`` (the promoted bundle + its enforced mode). Every
    operation is a commit, so ``git log`` is the deployment audit trail.
    """

    def __init__(self, repo: str | Path, *, author: str = "interlock-studio") -> None:
        self.repo = Path(repo)
        self._author = author
        if not (self.repo / ".git").exists():
            self.repo.mkdir(parents=True, exist_ok=True)
            _git(self.repo, "init", "-q", "-b", "main")
            _git(self.repo, "config", "user.email", "studio@interlock.local")
            _git(self.repo, "config", "user.name", author)
        (self.repo / "deploy" / "bundles").mkdir(parents=True, exist_ok=True)

    def _commit(self, message: str) -> str:
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", message)
        return _git(self.repo, "rev-parse", "HEAD")

    def propose(self, bundle: DeploymentBundle) -> str:
        """Write the SHADOW bundle as an immutable record and commit it."""
        path = self.repo / "deploy" / "bundles" / f"{bundle.bundle_digest}.json"
        record = {"mode": "SHADOW", "bundleDigest": bundle.bundle_digest, "body": bundle.body}
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        return self._commit(f"studio: propose {bundle.bundle_digest} (SHADOW)")

    def _load_bundle(self, bundle_digest: str) -> DeploymentBundle:
        path = self.repo / "deploy" / "bundles" / f"{bundle_digest}.json"
        if not path.exists():
            raise StudioDeploymentError(REASON_BUNDLE_UNKNOWN, "bundle is not in the review store")
        record = json.loads(path.read_text(encoding="utf-8"))
        body = record["body"]
        if canonical_digest(body) != bundle_digest:
            raise StudioDeploymentError(REASON_DIGEST_MISMATCH, "stored bundle digest does not match its body")
        return DeploymentBundle(body["architectureId"], str(body["version"]), bundle_digest, body)

    def active(self) -> dict[str, Any] | None:
        path = self.repo / "deploy" / "active.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def promote(
        self,
        bundle_digest: str,
        approvals: tuple[DeploymentApproval, ...],
        *,
        trusted_keys: Mapping[str, bytes],
    ) -> str:
        """Two-person-gated SHADOW→ENFORCE promotion of a proposed bundle."""
        bundle = self._load_bundle(bundle_digest)
        current = self.active()
        from_digest = current["bundleDigest"] if current else None
        statement = deployment_approval_statement(bundle, from_digest=from_digest, to_mode="ENFORCE")
        _verify_two_person(statement, approvals, trusted_keys)
        active = {
            "mode": "ENFORCE",
            "bundleDigest": bundle_digest,
            "promotedFrom": from_digest,
            "approvers": sorted({approval.approver_id for approval in approvals}),
        }
        (self.repo / "deploy" / "active.json").write_text(
            json.dumps(active, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        return self._commit(f"studio: promote {bundle_digest} SHADOW->ENFORCE")

    def rollback(self, target_digest: str) -> str:
        """Restore a previously proposed bundle as the active ENFORCE bundle."""
        self._load_bundle(target_digest)  # must be a known bundle
        current = self.active()
        active = {
            "mode": "ENFORCE",
            "bundleDigest": target_digest,
            "rolledBackFrom": current["bundleDigest"] if current else None,
        }
        (self.repo / "deploy" / "active.json").write_text(
            json.dumps(active, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        return self._commit(f"studio: rollback to {target_digest}")

    def history(self) -> tuple[str, ...]:
        log = _git(self.repo, "log", "--format=%s")
        return tuple(line for line in log.splitlines() if line)
