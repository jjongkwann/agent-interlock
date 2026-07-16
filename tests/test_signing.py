from __future__ import annotations

import unittest

from agent_interlock import SIGNING_ALGORITHM, sign_canonical, verify_canonical

KEY = b"interlock-test-signing-key-0000"
OTHER_KEY = b"a-different-key-1111111111111111"


class SigningTests(unittest.TestCase):
    def test_sign_verify_round_trip(self):
        body = {"event": "CONTROL_EVALUATED", "decision": "BLOCK", "count": 3}
        signature = sign_canonical(body, KEY)
        self.assertTrue(signature.startswith(f"{SIGNING_ALGORITHM}:"))
        self.assertTrue(verify_canonical(body, signature, KEY))

    def test_signature_is_canonical_not_key_order_sensitive(self):
        first = sign_canonical({"a": 1, "b": 2}, KEY)
        second = sign_canonical({"b": 2, "a": 1}, KEY)
        self.assertEqual(first, second)

    def test_tampered_payload_is_rejected(self):
        body = {"decision": "ALLOW"}
        signature = sign_canonical(body, KEY)
        self.assertFalse(verify_canonical({"decision": "BLOCK"}, signature, KEY))

    def test_wrong_key_is_rejected(self):
        body = {"decision": "ALLOW"}
        signature = sign_canonical(body, KEY)
        self.assertFalse(verify_canonical(body, signature, OTHER_KEY))

    def test_empty_key_is_refused(self):
        with self.assertRaises(ValueError):
            sign_canonical({"x": 1}, b"")
        self.assertFalse(verify_canonical({"x": 1}, "hmac-sha256:00", b""))

    def test_garbage_signature_is_rejected(self):
        self.assertFalse(verify_canonical({"x": 1}, "not-a-signature", KEY))
        self.assertFalse(verify_canonical({"x": 1}, 123, KEY))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
