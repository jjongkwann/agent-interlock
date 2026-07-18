from __future__ import annotations

import base64
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http_test_server import QuietThreadingHTTPServer

from agent_interlock import MCPJWKSVerifier, MCPOAuthError, OAuthSecurityProfile

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False

ISSUER = "https://idp.example/issuer"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_int(value: int, length: int) -> str:
    return _b64url(value.to_bytes(length, "big"))


def _make_jwt(header, payload, sign) -> str:
    segments = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    return f"{segments}.{_b64url(sign(segments.encode('ascii')))}"


def _payload(**overrides):
    base = {
        "iss": ISSUER,
        "sub": "user-1",
        "aud": "https://mcp.example/mcp",
        "resource": "https://mcp.example/mcp",
        "scope": "mcp.read mcp.call",
        "act": {"sub": "agent.support"},
        "exp": int(time.time()) + 300,
    }
    base.update(overrides)
    return base


class _JWKSServer:
    def __init__(self, keys):
        self._keys = keys

    def __enter__(self):
        keys = self._keys

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                body = json.dumps({"keys": keys}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_a):
                return

        self._server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def uri(self):
        return f"http://127.0.0.1:{self._server.server_port}/jwks"

    def __exit__(self, *_a):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def _profile():
    return OAuthSecurityProfile(
        allowed_authorization_server_hosts=frozenset({"127.0.0.1"}),
        allow_loopback_http=True,
        resolve_dns=False,
        max_redirect_hops=0,
    )


@unittest.skipUnless(_HAS_CRYPTO, "cryptography ('jwt' extra) is required")
class JWKSVerifierTests(unittest.TestCase):
    def setUp(self):
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.ed = ed25519.Ed25519PrivateKey.generate()

    def _rsa_jwk(self, kid="rsa-1"):
        numbers = self.rsa.public_key().public_numbers()
        return {
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "n": _b64url_int(numbers.n, (numbers.n.bit_length() + 7) // 8),
            "e": _b64url_int(numbers.e, (numbers.e.bit_length() + 7) // 8),
        }

    def _ec_jwk(self, kid="ec-1"):
        numbers = self.ec.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "kid": kid, "x": _b64url_int(numbers.x, 32), "y": _b64url_int(numbers.y, 32)}

    def _ed_jwk(self, kid="ed-1"):
        raw = self.ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": _b64url(raw)}

    def _rs256(self, payload, kid="rsa-1"):
        return _make_jwt({"alg": "RS256", "kid": kid}, payload, lambda data: self.rsa.sign(data, padding.PKCS1v15(), hashes.SHA256()))

    def _es256(self, payload, kid="ec-1"):
        def sign(data):
            r, s = decode_dss_signature(self.ec.sign(data, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")

        return _make_jwt({"alg": "ES256", "kid": kid}, payload, sign)

    def _eddsa(self, payload, kid="ed-1"):
        return _make_jwt({"alg": "EdDSA", "kid": kid}, payload, self.ed.sign)

    def _verifier(self, server):
        return MCPJWKSVerifier(server.uri, _profile(), expected_issuer=ISSUER)

    def test_rs256_token_maps_to_claims(self):
        with _JWKSServer([self._rsa_jwk()]) as server:
            claims = self._verifier(server)(self._rs256(_payload()))
            self.assertEqual(claims.issuer, ISSUER)
            self.assertEqual(claims.subject, "user-1")
            self.assertEqual(claims.actor, "agent.support")
            self.assertEqual(claims.audience, "https://mcp.example/mcp")
            self.assertEqual(claims.scopes, frozenset({"mcp.read", "mcp.call"}))

    def test_es256_token_is_verified(self):
        with _JWKSServer([self._ec_jwk()]) as server:
            claims = self._verifier(server)(self._es256(_payload()))
            self.assertEqual(claims.subject, "user-1")

    def test_eddsa_token_is_verified(self):
        with _JWKSServer([self._ed_jwk()]) as server:
            claims = self._verifier(server)(self._eddsa(_payload()))
            self.assertEqual(claims.subject, "user-1")

    def test_signature_from_a_different_key_is_rejected(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = _make_jwt({"alg": "RS256", "kid": "rsa-1"}, _payload(), lambda d: other.sign(d, padding.PKCS1v15(), hashes.SHA256()))
        with _JWKSServer([self._rsa_jwk()]) as server, self.assertRaises(MCPOAuthError) as raised:
            self._verifier(server)(forged)
        self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-JWT-SIGNATURE-INVALID")

    def test_alg_none_is_denied(self):
        token = _b64url(json.dumps({"alg": "none", "kid": "rsa-1"}).encode()) + "." + _b64url(json.dumps(_payload()).encode()) + "."
        with _JWKSServer([self._rsa_jwk()]) as server, self.assertRaises(MCPOAuthError) as raised:
            self._verifier(server)(token)
        self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-JWT-ALG-DENIED")

    def test_symmetric_alg_is_denied(self):
        token = _make_jwt({"alg": "HS256", "kid": "rsa-1"}, _payload(), lambda _d: b"forged-mac")
        with _JWKSServer([self._rsa_jwk()]) as server, self.assertRaises(MCPOAuthError) as raised:
            self._verifier(server)(token)
        self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-JWT-ALG-DENIED")

    def test_expired_token_is_rejected(self):
        with _JWKSServer([self._rsa_jwk()]) as server, self.assertRaises(MCPOAuthError) as raised:
            self._verifier(server)(self._rs256(_payload(exp=int(time.time()) - 10)))
        self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-TOKEN-EXPIRED")

    def test_unknown_kid_is_rejected(self):
        with _JWKSServer([self._rsa_jwk()]) as server, self.assertRaises(MCPOAuthError) as raised:
            self._verifier(server)(self._rs256(_payload(), kid="rsa-unknown"))
        self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-JWT-KEY-NOT-FOUND")

    def test_issuer_mismatch_is_rejected(self):
        with _JWKSServer([self._rsa_jwk()]) as server, self.assertRaises(MCPOAuthError) as raised:
            self._verifier(server)(self._rs256(_payload(iss="https://evil.example/issuer")))
        self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-TOKEN-ISSUER-MISMATCH")


if __name__ == "__main__":
    unittest.main()
