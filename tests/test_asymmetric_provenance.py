"""Asymmetric (Ed25519) publisher admission + KMS-style verifier plug point."""

from __future__ import annotations

import unittest

from agent_interlock import (
    ArtifactAdmissionPolicy,
    ArtifactProvenance,
    ArtifactSignature,
    ControlDecision,
    Ed25519PublisherVerifier,
    HMACPublisherVerifier,
    sign_artifact_provenance,
    sign_artifact_provenance_ed25519,
    sign_canonical_ed25519,
    verify_canonical_ed25519,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

DIGEST = "sha256:" + "b" * 64
PUBLISHER = "trusted-vendor"


def provenance(publisher: str = PUBLISHER) -> ArtifactProvenance:
    return ArtifactProvenance(
        server_id="tenant-a/prod/mail",
        publisher=publisher,
        artifact_digest=DIGEST,
        source_repository="https://github.com/trusted-vendor/mail",
        source_revision="a1b2c3",
        build_id="build-42",
    )


def keypair():
    private = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    raw_private = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw_private, raw_public


@unittest.skipUnless(HAVE_CRYPTO, "cryptography ('jwt' extra) required for Ed25519 tests")
class Ed25519AdmissionTests(unittest.TestCase):
    def test_valid_ed25519_signature_is_admitted(self):
        private, public = keypair()
        signature = sign_artifact_provenance_ed25519(provenance(), key_id="k1", private_key=private)
        policy = ArtifactAdmissionPolicy(publisher_verifiers={PUBLISHER: Ed25519PublisherVerifier({"k1": public})})
        decision = policy.admit(provenance(), signature)
        self.assertEqual(decision.decision, ControlDecision.ALLOW)
        self.assertTrue(decision.evidence["signatureVerified"])
        self.assertEqual(decision.evidence["signatureKeyId"], "k1")

    def test_signature_from_a_different_key_is_quarantined(self):
        signing_private, _ = keypair()
        _, other_public = keypair()
        signature = sign_artifact_provenance_ed25519(provenance(), key_id="k1", private_key=signing_private)
        policy = ArtifactAdmissionPolicy(
            publisher_verifiers={PUBLISHER: Ed25519PublisherVerifier({"k1": other_public})}
        )
        decision = policy.admit(provenance(), signature)
        self.assertEqual(decision.decision, ControlDecision.QUARANTINE)
        self.assertIn("L1-M4-SIGNATURE-INVALID", decision.reason_codes)

    def test_tampered_provenance_breaks_the_signature(self):
        private, public = keypair()
        signature = sign_artifact_provenance_ed25519(provenance(), key_id="k1", private_key=private)
        policy = ArtifactAdmissionPolicy(publisher_verifiers={PUBLISHER: Ed25519PublisherVerifier({"k1": public})})
        tampered = ArtifactProvenance(
            server_id="tenant-a/prod/mail",
            publisher=PUBLISHER,
            artifact_digest="sha256:" + "c" * 64,  # swapped artifact
            source_repository="https://github.com/trusted-vendor/mail",
            source_revision="a1b2c3",
            build_id="build-42",
        )
        decision = policy.admit(tampered, signature)
        self.assertEqual(decision.decision, ControlDecision.QUARANTINE)
        self.assertIn("L1-M4-SIGNATURE-INVALID", decision.reason_codes)

    def test_hmac_signature_is_not_accepted_by_the_ed25519_verifier(self):
        _, public = keypair()
        hmac_signature = sign_artifact_provenance(provenance(), key_id="k1", key=b"shared-secret-key")
        policy = ArtifactAdmissionPolicy(publisher_verifiers={PUBLISHER: Ed25519PublisherVerifier({"k1": public})})
        decision = policy.admit(provenance(), hmac_signature)
        self.assertEqual(decision.decision, ControlDecision.QUARANTINE)
        self.assertIn("L1-M4-SIGNATURE-INVALID", decision.reason_codes)

    def test_round_trip_helper(self):
        private, public = keypair()
        signature = sign_canonical_ed25519({"a": 1, "b": [2, 3]}, private)
        self.assertTrue(signature.startswith("ed25519:"))
        self.assertTrue(verify_canonical_ed25519({"a": 1, "b": [2, 3]}, signature, public))
        self.assertFalse(verify_canonical_ed25519({"a": 1, "b": [2, 4]}, signature, public))


class VerifierMixingTests(unittest.TestCase):
    """Behaviour that does not need the crypto backend."""

    def test_hmac_backward_compatible_constructor_still_works(self):
        key = b"a-shared-publisher-secret-000000"
        signature = sign_artifact_provenance(provenance(), key_id="k1", key=key)
        policy = ArtifactAdmissionPolicy({PUBLISHER: {"k1": key}})
        self.assertEqual(policy.admit(provenance(), signature).decision, ControlDecision.ALLOW)

    def test_wrong_algorithm_prefix_is_rejected_without_crypto(self):
        # An HMAC verifier must reject an ed25519-prefixed signature outright.
        policy = ArtifactAdmissionPolicy(
            publisher_verifiers={PUBLISHER: HMACPublisherVerifier({"k1": b"secret-key-000000000000000000000"})}
        )
        forged = ArtifactSignature("k1", "ed25519:" + "0" * 128)
        decision = policy.admit(provenance(), forged)
        self.assertEqual(decision.decision, ControlDecision.QUARANTINE)
        self.assertIn("L1-M4-SIGNATURE-INVALID", decision.reason_codes)

    def test_kms_style_custom_verifier_plugs_in(self):
        calls: list[tuple[str, str]] = []

        class RecordingKMSVerifier:
            """Stand-in for a KMS/Sigstore adapter: no local key material."""

            def verify(self, canonical_value, signature, key_id):
                calls.append((signature, key_id))
                return key_id == "kms-key" and signature == "kms:approved"

        policy = ArtifactAdmissionPolicy(publisher_verifiers={PUBLISHER: RecordingKMSVerifier()})
        approved = policy.admit(provenance(), ArtifactSignature("kms-key", "kms:approved"))
        self.assertEqual(approved.decision, ControlDecision.ALLOW)
        rejected = policy.admit(provenance(), ArtifactSignature("kms-key", "kms:forged"))
        self.assertEqual(rejected.decision, ControlDecision.QUARANTINE)
        self.assertEqual(calls, [("kms:approved", "kms-key"), ("kms:forged", "kms-key")])

    def test_empty_policy_is_rejected(self):
        with self.assertRaises(ValueError):
            ArtifactAdmissionPolicy()


if __name__ == "__main__":
    unittest.main()
