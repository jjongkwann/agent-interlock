"""Optional JWKS/JWT access-token verifier (needs the `jwt` extra: cryptography).

Mirrors the optional-psycopg pattern: importing this module never requires
cryptography; constructing MCPJWKSVerifier does. It verifies an asymmetric
compact JWS (RS256 / ES256 / EdDSA) against JWKS fetched over an SSRF-guarded
channel and maps standard claims to VerifiedAccessTokenClaims.

Symmetric algorithms and ``none`` are rejected up front: a verifier configured
with a public key must never accept an HMAC or unsigned token (algorithm
confusion). HMAC signing is HSM/KMS-free by design; production non-repudiation
still wants asymmetric keys, which this provides.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, Request, build_opener

from .mcp_oauth import (
    MCPOAuthError,
    MCPOAuthHTTPStatusError,
    OAuthSecurityProfile,
    VerifiedAccessTokenClaims,
    _introspection_actor,
    _json_mapping,
    _media_type,
    _NoRedirectHandler,
    _parse_scope,
    _single_audience,
    validate_oauth_url,
)

_ASYMMETRIC_ALGORITHMS = frozenset({"RS256", "ES256", "EdDSA"})


def _require_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise MCPOAuthError(
            "MCP-OAUTH-JWT-BACKEND-UNAVAILABLE",
            "JWKS/JWT verification requires the 'jwt' extra (cryptography)",
        ) from None


class MCPJWKSVerifier:
    """Verifies asymmetric JWS access tokens against cached JWKS."""

    def __init__(
        self,
        jwks_uri: str,
        profile: OAuthSecurityProfile,
        *,
        allowed_algorithms: frozenset[str] = _ASYMMETRIC_ALGORITHMS,
        expected_issuer: str | None = None,
        ssl_context: Any = None,
    ) -> None:
        _require_cryptography()
        self.profile = profile
        self.jwks_uri = validate_oauth_url(
            jwks_uri,
            allowed_hosts=profile.allowed_authorization_server_hosts,
            profile=profile,
            allow_query=True,
        )
        self.allowed_algorithms = frozenset(allowed_algorithms)
        if not self.allowed_algorithms or not self.allowed_algorithms <= _ASYMMETRIC_ALGORITHMS:
            raise MCPOAuthError(
                "MCP-OAUTH-JWT-ALG-UNSUPPORTED",
                "only asymmetric RS256/ES256/EdDSA algorithms are supported",
            )
        self.expected_issuer = expected_issuer
        handlers: list[Any] = [_NoRedirectHandler()]
        if ssl_context is not None:
            handlers.append(HTTPSHandler(context=ssl_context))
        self._opener = build_opener(*handlers)
        self._keys: dict[str, Mapping[str, Any]] = {}
        self._lock = threading.RLock()

    def __call__(self, access_token: str) -> VerifiedAccessTokenClaims:
        header, payload, signing_input, signature = _split_jwt(access_token)
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self.allowed_algorithms:
            raise MCPOAuthError("MCP-OAUTH-JWT-ALG-DENIED", "JWT alg is not an allowed asymmetric algorithm")
        kid = header.get("kid")
        jwk = self._jwk_for(kid)
        _verify_signature(jwk, alg, signing_input, signature)
        return self._map_claims(payload)

    def _jwk_for(self, kid: Any) -> Mapping[str, Any]:
        if not isinstance(kid, str) or not kid:
            raise MCPOAuthError("MCP-OAUTH-JWT-KID-MISSING", "JWT header has no key id")
        with self._lock:
            jwk = self._keys.get(kid)
        if jwk is None:
            refreshed = self._fetch_jwks()
            with self._lock:
                self._keys = refreshed
                jwk = self._keys.get(kid)
        if jwk is None:
            raise MCPOAuthError("MCP-OAUTH-JWT-KEY-NOT-FOUND", "no JWKS key matches the JWT key id")
        return jwk

    def _fetch_jwks(self) -> dict[str, Mapping[str, Any]]:
        request = Request(self.jwks_uri, method="GET", headers={"Accept": "application/json", "Cache-Control": "no-store"})
        try:
            response = self._opener.open(request, timeout=self.profile.timeout_seconds)
        except HTTPError as error:
            status = error.code
            error.close()
            raise MCPOAuthHTTPStatusError(status, reason_code="MCP-OAUTH-JWKS-STATUS") from None
        except (URLError, TimeoutError, OSError):
            raise MCPOAuthError("MCP-OAUTH-JWKS-CONNECTION-FAILED", "JWKS request failed") from None
        try:
            if response.status != 200:
                raise MCPOAuthHTTPStatusError(response.status, reason_code="MCP-OAUTH-JWKS-STATUS")
            if _media_type(response.headers.get("Content-Type")) != "application/json":
                raise MCPOAuthError("MCP-OAUTH-CONTENT-TYPE-INVALID", "JWKS response must be JSON")
            payload = response.read(self.profile.max_response_bytes + 1)
            if len(payload) > self.profile.max_response_bytes:
                raise MCPOAuthError("MCP-OAUTH-RESPONSE-TOO-LARGE", "JWKS response is too large")
        finally:
            response.close()
        value = _json_mapping(payload)
        keys = value.get("keys")
        if not isinstance(keys, list):
            raise MCPOAuthError("MCP-OAUTH-JWKS-INVALID", "JWKS must contain a keys array")
        result: dict[str, Mapping[str, Any]] = {}
        for jwk in keys:
            if isinstance(jwk, Mapping) and isinstance(jwk.get("kid"), str) and jwk["kid"]:
                result[jwk["kid"]] = dict(jwk)
        return result

    def _map_claims(self, payload: Mapping[str, Any]) -> VerifiedAccessTokenClaims:
        issuer = _required_claim(payload, "iss")
        if self.expected_issuer is not None and issuer != self.expected_issuer:
            raise MCPOAuthError("MCP-OAUTH-TOKEN-ISSUER-MISMATCH", "verified token issuer does not match")
        subject = _required_claim(payload, "sub")
        expires = payload.get("exp")
        if not isinstance(expires, int) or isinstance(expires, bool) or expires <= 0:
            raise MCPOAuthError("MCP-OAUTH-JWT-CLAIMS-INVALID", "JWT exp is invalid")
        now = time.time()
        if expires <= now:
            raise MCPOAuthError("MCP-OAUTH-TOKEN-EXPIRED", "verified access token is expired")
        not_before = payload.get("nbf")
        if not_before is not None:
            if not isinstance(not_before, int) or isinstance(not_before, bool) or not_before > now:
                raise MCPOAuthError("MCP-OAUTH-TOKEN-NOT-YET-VALID", "verified access token is not yet valid")
        audience = _single_audience(payload.get("aud"))
        resource_value = payload.get("resource")
        if resource_value is None:
            resource = audience
        elif isinstance(resource_value, str) and resource_value:
            resource = resource_value
        else:
            raise MCPOAuthError("MCP-OAUTH-JWT-CLAIMS-INVALID", "JWT resource claim is invalid")
        return VerifiedAccessTokenClaims(
            issuer=issuer,
            subject=subject,
            actor=_introspection_actor(payload, subject),
            audience=audience,
            resource=resource,
            scopes=_jwt_scopes(payload),
            expires_at_epoch=float(expires),
        )


def _split_jwt(token: str) -> tuple[Mapping[str, Any], Mapping[str, Any], bytes, bytes]:
    if not isinstance(token, str) or token.count(".") != 2 or "\r" in token or "\n" in token:
        raise MCPOAuthError("MCP-OAUTH-JWT-MALFORMED", "access token is not a compact JWS")
    header_b64, payload_b64, signature_b64 = token.split(".")
    header = _b64url_json(header_b64)
    payload = _b64url_json(payload_b64)
    signature = _b64url_bytes(signature_b64)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return header, payload, signing_input, signature


def _verify_signature(jwk: Mapping[str, Any], alg: str, signing_input: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    kty = jwk.get("kty")
    try:
        if alg == "RS256":
            if kty != "RSA":
                raise MCPOAuthError("MCP-OAUTH-JWT-KEY-MISMATCH", "RS256 requires an RSA key")
            _rsa_public_key(jwk).verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ES256":
            if kty != "EC" or jwk.get("crv") != "P-256":
                raise MCPOAuthError("MCP-OAUTH-JWT-KEY-MISMATCH", "ES256 requires a P-256 EC key")
            if len(signature) != 64:
                raise MCPOAuthError("MCP-OAUTH-JWT-SIGNATURE-INVALID", "ES256 signature length is invalid")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            _ec_public_key(jwk).verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
        elif alg == "EdDSA":
            if kty != "OKP" or jwk.get("crv") != "Ed25519":
                raise MCPOAuthError("MCP-OAUTH-JWT-KEY-MISMATCH", "EdDSA requires an Ed25519 OKP key")
            ed25519.Ed25519PublicKey.from_public_bytes(_b64url_bytes(_required_jwk(jwk, "x"))).verify(signature, signing_input)
        else:  # pragma: no cover - alg already allow-listed
            raise MCPOAuthError("MCP-OAUTH-JWT-ALG-DENIED", "unsupported JWT algorithm")
    except InvalidSignature:
        raise MCPOAuthError("MCP-OAUTH-JWT-SIGNATURE-INVALID", "JWT signature verification failed") from None


def _rsa_public_key(jwk: Mapping[str, Any]):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    n = int.from_bytes(_b64url_bytes(_required_jwk(jwk, "n")), "big")
    e = int.from_bytes(_b64url_bytes(_required_jwk(jwk, "e")), "big")
    return RSAPublicNumbers(e, n).public_key()


def _ec_public_key(jwk: Mapping[str, Any]):
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicNumbers

    x = int.from_bytes(_b64url_bytes(_required_jwk(jwk, "x")), "big")
    y = int.from_bytes(_b64url_bytes(_required_jwk(jwk, "y")), "big")
    return EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()


def _jwt_scopes(payload: Mapping[str, Any]) -> frozenset[str]:
    scope = payload.get("scope")
    if isinstance(scope, str) and scope:
        return frozenset(_parse_scope(scope))
    scp = payload.get("scp")
    if isinstance(scp, list) and all(isinstance(item, str) and item for item in scp):
        return frozenset(scp)
    return frozenset()


def _required_claim(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise MCPOAuthError("MCP-OAUTH-JWT-CLAIMS-INVALID", f"JWT {key} claim is invalid")
    return value


def _required_jwk(jwk: Mapping[str, Any], key: str) -> str:
    value = jwk.get(key)
    if not isinstance(value, str) or not value:
        raise MCPOAuthError("MCP-OAUTH-JWKS-INVALID", f"JWKS key field {key} is invalid")
    return value


def _b64url_bytes(value: str) -> bytes:
    if not isinstance(value, str) or any(character in value for character in "+/ \t"):
        raise MCPOAuthError("MCP-OAUTH-JWT-MALFORMED", "JWT segment is not base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as error:  # type: ignore[attr-defined]
        raise MCPOAuthError("MCP-OAUTH-JWT-MALFORMED", "JWT segment is not base64url") from error


def _b64url_json(value: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(_b64url_bytes(value).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MCPOAuthError("MCP-OAUTH-JWT-MALFORMED", "JWT segment is not JSON") from error
    if not isinstance(parsed, Mapping):
        raise MCPOAuthError("MCP-OAUTH-JWT-MALFORMED", "JWT segment must be a JSON object")
    return parsed
