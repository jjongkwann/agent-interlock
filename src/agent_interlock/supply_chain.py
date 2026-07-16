"""M4 artifact provenance admission with publisher-bound signatures.

The reference implementation uses the project's canonical HMAC signature
helper. Production deployments can keep the admission contract while replacing
the signer/verifier with Sigstore, a package registry verifier, or KMS-backed
asymmetric keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from .canonical import canonical_digest
from .models import ControlDecision
from .signing import sign_canonical, verify_canonical


REASON_UNTRUSTED_PUBLISHER = "L1-M4-UNTRUSTED-PUBLISHER"
REASON_SIGNATURE_INVALID = "L1-M4-SIGNATURE-INVALID"
REASON_PROVENANCE_DENIED = "L1-M4-PROVENANCE-DENIED"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")


def _require_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _canonical_repository(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as error:
        raise ValueError("source_repository is invalid") from error
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("source_repository must be a credential-free HTTPS URL")
    port = f":{parsed.port}" if parsed.port and parsed.port != 443 else ""
    display_host = f"[{host}]" if ":" in host else host
    path = parsed.path.rstrip("/")
    return f"https://{display_host}{port}{path}"


@dataclass(frozen=True, slots=True)
class ArtifactProvenance:
    server_id: str
    publisher: str
    artifact_digest: str
    source_repository: str
    source_revision: str
    build_id: str

    def __post_init__(self) -> None:
        _require_identifier(self.server_id, "server_id")
        _require_identifier(self.publisher, "publisher")
        _require_identifier(self.source_revision, "source_revision")
        _require_identifier(self.build_id, "build_id")
        if _DIGEST.fullmatch(self.artifact_digest) is None:
            raise ValueError("artifact_digest must be a sha256 digest")
        object.__setattr__(self, "source_repository", _canonical_repository(self.source_repository))

    def canonical_value(self) -> dict[str, str]:
        return {
            "serverId": self.server_id,
            "publisher": self.publisher,
            "artifactDigest": self.artifact_digest,
            "sourceRepository": self.source_repository,
            "sourceRevision": self.source_revision,
            "buildId": self.build_id,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_value())


@dataclass(frozen=True, slots=True)
class ArtifactSignature:
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        _require_identifier(self.key_id, "key_id")
        if not isinstance(self.signature, str) or not self.signature:
            raise ValueError("signature is required")


def sign_artifact_provenance(
    provenance: ArtifactProvenance,
    *,
    key_id: str,
    key: bytes,
) -> ArtifactSignature:
    """Sign every provenance field and identify the publisher verification key."""
    return ArtifactSignature(key_id, sign_canonical(provenance.canonical_value(), key))


@dataclass(frozen=True, slots=True)
class ArtifactAdmissionDecision:
    decision: ControlDecision
    reason_codes: tuple[str, ...]
    evidence: Mapping[str, Any]

    @property
    def admitted(self) -> bool:
        return self.decision is ControlDecision.ALLOW


class ArtifactAdmissionPolicy:
    """Allow only exact repositories signed by a trusted publisher key."""

    def __init__(
        self,
        trusted_publisher_keys: Mapping[str, Mapping[str, bytes]],
        *,
        allowed_repositories: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        self._trusted_keys = {
            publisher: {key_id: key for key_id, key in keys.items() if key}
            for publisher, keys in trusted_publisher_keys.items()
            if publisher and keys
        }
        self._allowed_repositories = {
            publisher: frozenset(_canonical_repository(repository) for repository in repositories)
            for publisher, repositories in (allowed_repositories or {}).items()
        }
        if not self._trusted_keys:
            raise ValueError("at least one trusted publisher key is required")

    def admit(
        self,
        provenance: ArtifactProvenance | None,
        signature: ArtifactSignature | None,
    ) -> ArtifactAdmissionDecision:
        publisher = provenance.publisher if provenance else ""
        evidence: dict[str, Any] = {
            "publisher": publisher,
            "artifactDigest": provenance.artifact_digest if provenance else None,
            "provenanceDigest": provenance.digest if provenance else None,
            "sourceRepository": provenance.source_repository if provenance else None,
            "sourceRevision": provenance.source_revision if provenance else None,
            "buildId": provenance.build_id if provenance else None,
            "signatureKeyId": signature.key_id if signature else None,
            "signatureVerified": False,
        }
        keys = self._trusted_keys.get(publisher)
        if provenance is None or keys is None:
            return ArtifactAdmissionDecision(
                ControlDecision.QUARANTINE,
                (REASON_UNTRUSTED_PUBLISHER,),
                evidence,
            )
        repositories = self._allowed_repositories.get(publisher)
        if repositories is not None and provenance.source_repository not in repositories:
            return ArtifactAdmissionDecision(
                ControlDecision.QUARANTINE,
                (REASON_PROVENANCE_DENIED,),
                evidence,
            )
        key = keys.get(signature.key_id) if signature else None
        if key is None or not verify_canonical(
            provenance.canonical_value(),
            signature.signature if signature else "",
            key or b"",
        ):
            return ArtifactAdmissionDecision(
                ControlDecision.QUARANTINE,
                (REASON_SIGNATURE_INVALID,),
                evidence,
            )
        evidence["signatureVerified"] = True
        return ArtifactAdmissionDecision(ControlDecision.ALLOW, (), evidence)
