"""OAuth 2.1 security helpers for MCP Streamable HTTP clients.

The module deliberately separates browser authorization, token verification, and
MCP transport.  It does not decode an unsigned JWT or automatically replay an
MCP request after an authentication failure.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .models import CredentialClaims


_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_TOKEN_RE = re.compile(rf"^{_TOKEN}$")
_AUTH_PARAM_RE = re.compile(rf"^({_TOKEN})\s*=\s*(.*)$")
_CHALLENGE_RE = re.compile(rf"^({_TOKEN})(?:\s+(.*))?$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")
_PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class MCPOAuthError(RuntimeError):
    """Fail-closed OAuth error with a stable, non-secret reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class MCPOAuthHTTPStatusError(MCPOAuthError):
    def __init__(self, status: int, *, reason_code: str = "MCP-OAUTH-HTTP-STATUS") -> None:
        super().__init__(reason_code, f"OAuth endpoint returned HTTP status {status}")
        self.status = status


@dataclass(frozen=True, slots=True)
class BearerChallenge:
    resource_metadata: str | None = None
    scopes: tuple[str, ...] = ()
    error: str | None = None


def parse_bearer_challenge(value: str) -> BearerChallenge:
    """Parse the first Bearer challenge without accepting duplicate parameters."""
    if not isinstance(value, str) or not value or len(value) > 8192 or "\r" in value or "\n" in value:
        raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "WWW-Authenticate is invalid")
    segments = _split_quoted_list(value)
    current_scheme: str | None = None
    bearer_parameters: dict[str, str] | None = None
    for segment in segments:
        challenge_match = _CHALLENGE_RE.fullmatch(segment.strip())
        parameter_match = _AUTH_PARAM_RE.fullmatch(segment.strip())
        starts_challenge = bool(
            challenge_match
            and (
                parameter_match is None
                or " " in segment.strip()
                and challenge_match.group(2) is not None
                and _AUTH_PARAM_RE.fullmatch(challenge_match.group(2).strip()) is not None
            )
        )
        if starts_challenge:
            current_scheme = challenge_match.group(1).casefold()
            if current_scheme == "bearer" and bearer_parameters is None:
                bearer_parameters = {}
            remainder = challenge_match.group(2)
            if remainder:
                _add_auth_parameter(current_scheme, remainder, bearer_parameters)
            continue
        if current_scheme is None:
            raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "WWW-Authenticate is malformed")
        _add_auth_parameter(current_scheme, segment, bearer_parameters)
    if bearer_parameters is None:
        raise MCPOAuthError("MCP-OAUTH-BEARER-MISSING", "Bearer challenge is missing")
    resource_metadata = bearer_parameters.get("resource_metadata")
    if resource_metadata is not None and not resource_metadata:
        raise MCPOAuthError("MCP-OAUTH-RESOURCE-METADATA-INVALID", "resource metadata URL is empty")
    scope_value = bearer_parameters.get("scope", "")
    scopes = _parse_scope(scope_value) if scope_value else ()
    return BearerChallenge(
        resource_metadata=resource_metadata,
        scopes=scopes,
        error=bearer_parameters.get("error"),
    )


@dataclass(frozen=True, slots=True)
class OAuthSecurityProfile:
    """Explicit network trust boundary for OAuth discovery and token exchange."""

    allowed_authorization_server_hosts: frozenset[str]
    allowed_authorization_server_issuers: frozenset[str] = frozenset()
    allowed_metadata_hosts: frozenset[str] = frozenset()
    allow_loopback_http: bool = False
    resolve_dns: bool = True
    timeout_seconds: float = 5.0
    max_response_bytes: int = 262_144
    max_redirect_hops: int = 0

    def __post_init__(self) -> None:
        authorization_hosts = frozenset(_canonical_host(item) for item in self.allowed_authorization_server_hosts)
        metadata_hosts = frozenset(_canonical_host(item) for item in self.allowed_metadata_hosts)
        if not authorization_hosts:
            raise ValueError("at least one authorization server host must be allowed")
        if self.timeout_seconds <= 0 or self.max_response_bytes <= 0 or self.max_redirect_hops < 0:
            raise ValueError("OAuth network limits are invalid")
        object.__setattr__(self, "allowed_authorization_server_hosts", authorization_hosts)
        object.__setattr__(self, "allowed_metadata_hosts", metadata_hosts)
        if any(not isinstance(item, str) or not item for item in self.allowed_authorization_server_issuers):
            raise ValueError("allowed authorization server issuers must be non-empty strings")


@dataclass(frozen=True, slots=True)
class ProtectedResourceMetadata:
    resource: str
    authorization_servers: tuple[str, ...]
    scopes_supported: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorizationServerMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    code_challenge_methods_supported: tuple[str, ...]
    scopes_supported: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MCPAuthorizationDiscovery:
    protected_resource: ProtectedResourceMetadata
    authorization_server: AuthorizationServerMetadata
    required_scopes: tuple[str, ...] = ()
    protected_resource_metadata_url: str = ""
    authorization_server_metadata_url: str = ""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class MCPProtectedResourceDiscovery:
    """Discover and validate RFC 9728 and authorization-server metadata."""

    def __init__(
        self,
        endpoint: str,
        profile: OAuthSecurityProfile,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.profile = profile
        resource_host = _host_from_url(endpoint)
        self.resource = validate_oauth_url(
            endpoint,
            allowed_hosts=frozenset({resource_host}),
            profile=profile,
            allow_query=False,
        )
        self._allowed_issuers = frozenset(
            validate_oauth_url(
                issuer,
                allowed_hosts=profile.allowed_authorization_server_hosts,
                profile=profile,
                allow_query=False,
            )
            for issuer in profile.allowed_authorization_server_issuers
        )
        handlers: list[Any] = [_NoRedirectHandler()]
        if ssl_context is not None:
            handlers.append(HTTPSHandler(context=ssl_context))
        self._opener = build_opener(*handlers)

    def protected_resource_candidates(self, challenge: BearerChallenge | None = None) -> tuple[str, ...]:
        parsed = urlsplit(self.resource)
        origin = _origin(parsed)
        path = parsed.path.strip("/")
        candidates: list[str] = []
        if challenge and challenge.resource_metadata:
            metadata_hosts = self.profile.allowed_metadata_hosts | frozenset({_canonical_host(parsed.hostname or "")})
            candidates.append(
                validate_oauth_url(
                    challenge.resource_metadata,
                    allowed_hosts=metadata_hosts,
                    profile=self.profile,
                    allow_query=False,
                )
            )
        if path:
            candidates.append(f"{origin}/.well-known/oauth-protected-resource/{path}")
        candidates.append(f"{origin}/.well-known/oauth-protected-resource")
        return tuple(dict.fromkeys(candidates))

    def authorization_server_candidates(self, issuer: str) -> tuple[str, ...]:
        canonical_issuer = validate_oauth_url(
            issuer,
            allowed_hosts=self.profile.allowed_authorization_server_hosts,
            profile=self.profile,
            allow_query=False,
        )
        parsed = urlsplit(canonical_issuer)
        origin = _origin(parsed)
        issuer_path = parsed.path.strip("/")
        if issuer_path:
            return (
                f"{origin}/.well-known/oauth-authorization-server/{issuer_path}",
                f"{origin}/.well-known/openid-configuration/{issuer_path}",
                f"{origin}/{issuer_path}/.well-known/openid-configuration",
            )
        return (
            f"{origin}/.well-known/oauth-authorization-server",
            f"{origin}/.well-known/openid-configuration",
        )

    def discover(self, www_authenticate: str | None = None) -> MCPAuthorizationDiscovery:
        challenge = parse_bearer_challenge(www_authenticate) if www_authenticate else None
        resource_value: Mapping[str, Any] | None = None
        resource_metadata_url = ""
        metadata_hosts = self.profile.allowed_metadata_hosts | frozenset({_host_from_url(self.resource)})
        for candidate in self.protected_resource_candidates(challenge):
            try:
                resource_value, resource_metadata_url = self._get_json(candidate, metadata_hosts)
                break
            except MCPOAuthHTTPStatusError as error:
                if error.status != 404:
                    raise
        if resource_value is None:
            raise MCPOAuthError(
                "MCP-OAUTH-RESOURCE-METADATA-NOT-FOUND",
                "OAuth protected resource metadata was not found",
            )
        protected_resource = self._parse_protected_resource(resource_value)
        if protected_resource.resource != self.resource:
            raise MCPOAuthError(
                "MCP-OAUTH-RESOURCE-MISMATCH",
                "protected resource metadata does not identify the configured MCP endpoint",
            )
        if challenge and challenge.scopes and protected_resource.scopes_supported:
            if not set(challenge.scopes).issubset(protected_resource.scopes_supported):
                raise MCPOAuthError(
                    "MCP-OAUTH-SCOPE-UNSUPPORTED",
                    "Bearer challenge requests an unsupported scope",
                )
        issuer = protected_resource.authorization_servers[0]
        server_value: Mapping[str, Any] | None = None
        server_metadata_url = ""
        for candidate in self.authorization_server_candidates(issuer):
            try:
                server_value, server_metadata_url = self._get_json(
                    candidate,
                    self.profile.allowed_authorization_server_hosts,
                )
                break
            except MCPOAuthHTTPStatusError as error:
                if error.status != 404:
                    raise
        if server_value is None:
            raise MCPOAuthError(
                "MCP-OAUTH-AS-METADATA-NOT-FOUND",
                "authorization server metadata was not found",
            )
        authorization_server = self._parse_authorization_server(server_value, issuer)
        return MCPAuthorizationDiscovery(
            protected_resource=protected_resource,
            authorization_server=authorization_server,
            required_scopes=challenge.scopes if challenge else (),
            protected_resource_metadata_url=resource_metadata_url,
            authorization_server_metadata_url=server_metadata_url,
        )

    def _parse_protected_resource(self, value: Mapping[str, Any]) -> ProtectedResourceMetadata:
        resource_value = _required_string(value, "resource", "MCP-OAUTH-RESOURCE-METADATA-INVALID")
        resource_host = _host_from_url(self.resource)
        resource = validate_oauth_url(
            resource_value,
            allowed_hosts=frozenset({resource_host}),
            profile=self.profile,
            allow_query=False,
        )
        authorization_servers = _string_array(
            value.get("authorization_servers"),
            "MCP-OAUTH-RESOURCE-METADATA-INVALID",
            required=True,
        )
        canonical_issuers = tuple(
            validate_oauth_url(
                item,
                allowed_hosts=self.profile.allowed_authorization_server_hosts,
                profile=self.profile,
                allow_query=False,
            )
            for item in authorization_servers
        )
        if self._allowed_issuers and any(item not in self._allowed_issuers for item in canonical_issuers):
            raise MCPOAuthError(
                "MCP-OAUTH-ISSUER-NOT-ALLOWED",
                "protected resource selected an authorization server issuer outside the trust policy",
            )
        scopes = _string_array(
            value.get("scopes_supported"),
            "MCP-OAUTH-RESOURCE-METADATA-INVALID",
        )
        for scope in scopes:
            _validate_scope_token(scope)
        return ProtectedResourceMetadata(resource, canonical_issuers, scopes)

    def _parse_authorization_server(
        self,
        value: Mapping[str, Any],
        expected_issuer: str,
    ) -> AuthorizationServerMetadata:
        issuer = validate_oauth_url(
            _required_string(value, "issuer", "MCP-OAUTH-AS-METADATA-INVALID"),
            allowed_hosts=self.profile.allowed_authorization_server_hosts,
            profile=self.profile,
            allow_query=False,
        )
        canonical_expected = validate_oauth_url(
            expected_issuer,
            allowed_hosts=self.profile.allowed_authorization_server_hosts,
            profile=self.profile,
            allow_query=False,
        )
        if issuer != canonical_expected:
            raise MCPOAuthError("MCP-OAUTH-ISSUER-MISMATCH", "authorization server issuer does not match")
        authorization_endpoint = validate_oauth_url(
            _required_string(value, "authorization_endpoint", "MCP-OAUTH-AS-METADATA-INVALID"),
            allowed_hosts=self.profile.allowed_authorization_server_hosts,
            profile=self.profile,
            allow_query=True,
        )
        token_endpoint = validate_oauth_url(
            _required_string(value, "token_endpoint", "MCP-OAUTH-AS-METADATA-INVALID"),
            allowed_hosts=self.profile.allowed_authorization_server_hosts,
            profile=self.profile,
            allow_query=True,
        )
        methods = _string_array(
            value.get("code_challenge_methods_supported"),
            "MCP-OAUTH-PKCE-S256-REQUIRED",
            required=True,
        )
        if "S256" not in methods:
            raise MCPOAuthError("MCP-OAUTH-PKCE-S256-REQUIRED", "authorization server must support PKCE S256")
        scopes = _string_array(value.get("scopes_supported"), "MCP-OAUTH-AS-METADATA-INVALID")
        for scope in scopes:
            _validate_scope_token(scope)
        return AuthorizationServerMetadata(
            issuer=issuer,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            code_challenge_methods_supported=methods,
            scopes_supported=scopes,
        )

    def _get_json(self, url: str, allowed_hosts: frozenset[str]) -> tuple[Mapping[str, Any], str]:
        current = validate_oauth_url(url, allowed_hosts=allowed_hosts, profile=self.profile, allow_query=True)
        for hop in range(self.profile.max_redirect_hops + 1):
            request = Request(
                current,
                method="GET",
                headers={"Accept": "application/json", "Cache-Control": "no-store"},
            )
            try:
                response = self._opener.open(request, timeout=self.profile.timeout_seconds)
            except HTTPError as error:
                status = error.code
                location = error.headers.get("Location") if error.headers else None
                error.close()
                if status in _REDIRECT_STATUSES and location:
                    if hop >= self.profile.max_redirect_hops:
                        raise MCPOAuthError(
                            "MCP-OAUTH-REDIRECT-DENIED",
                            "OAuth metadata redirect exceeds the configured hop limit",
                        ) from error
                    current = validate_oauth_url(
                        urljoin(current, location),
                        allowed_hosts=allowed_hosts,
                        profile=self.profile,
                        allow_query=True,
                    )
                    continue
                raise MCPOAuthHTTPStatusError(status) from error
            except (URLError, TimeoutError, OSError) as error:
                raise MCPOAuthError("MCP-OAUTH-CONNECTION-FAILED", "OAuth metadata request failed") from error
            try:
                if response.status != 200:
                    raise MCPOAuthHTTPStatusError(response.status)
                if _media_type(response.headers.get("Content-Type")) not in {
                    "application/json",
                    "application/oauth-authz-server",
                }:
                    raise MCPOAuthError(
                        "MCP-OAUTH-CONTENT-TYPE-INVALID",
                        "OAuth metadata response must be JSON",
                    )
                payload = response.read(self.profile.max_response_bytes + 1)
                if len(payload) > self.profile.max_response_bytes:
                    raise MCPOAuthError("MCP-OAUTH-RESPONSE-TOO-LARGE", "OAuth metadata response is too large")
            finally:
                response.close()
            return _json_mapping(payload), current
        raise AssertionError("unreachable OAuth redirect loop")


@dataclass(slots=True)
class OAuthAuthorizationTransaction:
    client_id: str
    redirect_uri: str
    resource: str
    scopes: tuple[str, ...]
    state: str = field(repr=False)
    code_verifier: str = field(repr=False)
    authorization_uri: str = field(repr=False)
    expires_at_epoch: float
    callback_consumed: bool = False
    callback_validated: bool = False
    exchange_consumed: bool = False
    authorization_code_digest: str | None = field(default=None, repr=False)


class MCPAuthorizationCodeFlow:
    """Create a PKCE authorization request and validate its exact callback."""

    def __init__(
        self,
        discovery: MCPAuthorizationDiscovery,
        profile: OAuthSecurityProfile,
        *,
        client_id: str,
        registered_redirect_uris: frozenset[str],
        allow_loopback_http: bool = False,
        transaction_ttl_seconds: int = 300,
    ) -> None:
        if not client_id or not registered_redirect_uris or transaction_ttl_seconds <= 0:
            raise ValueError("OAuth client registration and transaction TTL are required")
        self.discovery = discovery
        self.profile = profile
        self.client_id = client_id
        self.registered_redirect_uris = registered_redirect_uris
        self.allow_loopback_http = allow_loopback_http
        self.transaction_ttl_seconds = transaction_ttl_seconds
        validate_oauth_url(
            discovery.authorization_server.authorization_endpoint,
            allowed_hosts=profile.allowed_authorization_server_hosts,
            profile=profile,
            allow_query=True,
        )
        if "S256" not in discovery.authorization_server.code_challenge_methods_supported:
            raise MCPOAuthError("MCP-OAUTH-PKCE-S256-REQUIRED", "authorization server must support PKCE S256")
        for redirect_uri in registered_redirect_uris:
            _validate_redirect_uri(redirect_uri, allow_loopback_http=allow_loopback_http)

    def begin(
        self,
        *,
        redirect_uri: str,
        scopes: Sequence[str] | None = None,
        now_epoch: float | None = None,
    ) -> OAuthAuthorizationTransaction:
        if redirect_uri not in self.registered_redirect_uris:
            raise MCPOAuthError("MCP-OAUTH-REDIRECT-URI-MISMATCH", "redirect URI is not exactly registered")
        _validate_redirect_uri(redirect_uri, allow_loopback_http=self.allow_loopback_http)
        requested = tuple(dict.fromkeys(scopes or self.discovery.required_scopes))
        for scope in requested:
            _validate_scope_token(scope)
        if self.discovery.required_scopes and set(requested) != set(self.discovery.required_scopes):
            raise MCPOAuthError(
                "MCP-OAUTH-CHALLENGE-SCOPE-MISMATCH",
                "authorization request must use the challenge scope for this request",
            )
        supported = self.discovery.protected_resource.scopes_supported
        if supported and not set(requested).issubset(supported):
            raise MCPOAuthError("MCP-OAUTH-SCOPE-UNSUPPORTED", "authorization request contains unsupported scope")
        verifier = generate_pkce_verifier()
        state = secrets.token_urlsafe(32)
        parameters = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(requested),
            "state": state,
            "code_challenge": pkce_s256_challenge(verifier),
            "code_challenge_method": "S256",
            "resource": self.discovery.protected_resource.resource,
        }
        authorization_uri = _append_oauth_query(
            self.discovery.authorization_server.authorization_endpoint,
            parameters,
        )
        now = time.time() if now_epoch is None else now_epoch
        return OAuthAuthorizationTransaction(
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            resource=self.discovery.protected_resource.resource,
            scopes=requested,
            state=state,
            code_verifier=verifier,
            authorization_uri=authorization_uri,
            expires_at_epoch=now + self.transaction_ttl_seconds,
        )

    def validate_callback(
        self,
        transaction: OAuthAuthorizationTransaction,
        callback_uri: str,
        *,
        now_epoch: float | None = None,
    ) -> str:
        if transaction.callback_consumed:
            raise MCPOAuthError("MCP-OAUTH-CALLBACK-REPLAY", "OAuth callback transaction was already consumed")
        transaction.callback_consumed = True
        now = time.time() if now_epoch is None else now_epoch
        if now > transaction.expires_at_epoch:
            raise MCPOAuthError("MCP-OAUTH-TRANSACTION-EXPIRED", "OAuth authorization transaction expired")
        parsed = urlsplit(callback_uri)
        expected = urlsplit(transaction.redirect_uri)
        if parsed.fragment or (parsed.scheme, parsed.netloc, parsed.path) != (
            expected.scheme,
            expected.netloc,
            expected.path,
        ):
            raise MCPOAuthError("MCP-OAUTH-REDIRECT-URI-MISMATCH", "OAuth callback URI does not match")
        parameters = _unique_query_parameters(parsed.query)
        returned_state = parameters.get("state")
        if returned_state is None or not secrets.compare_digest(returned_state, transaction.state):
            raise MCPOAuthError("MCP-OAUTH-STATE-MISMATCH", "OAuth state does not match")
        code = parameters.get("code")
        oauth_error = parameters.get("error")
        if bool(code) == bool(oauth_error):
            raise MCPOAuthError("MCP-OAUTH-CALLBACK-INVALID", "OAuth callback must contain one code or error")
        if oauth_error:
            raise MCPOAuthError("MCP-OAUTH-AUTHORIZATION-DENIED", "authorization server denied the request")
        if not code or any(ord(character) < 0x21 for character in code):
            raise MCPOAuthError("MCP-OAUTH-CODE-INVALID", "authorization code is invalid")
        transaction.authorization_code_digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        transaction.callback_validated = True
        return code


def generate_pkce_verifier() -> str:
    verifier = secrets.token_urlsafe(64).rstrip("=")
    if not _PKCE_VERIFIER_RE.fullmatch(verifier):
        raise MCPOAuthError("MCP-OAUTH-PKCE-INVALID", "generated PKCE verifier is invalid")
    return verifier


def pkce_s256_challenge(verifier: str) -> str:
    if not isinstance(verifier, str) or not _PKCE_VERIFIER_RE.fullmatch(verifier):
        raise MCPOAuthError("MCP-OAUTH-PKCE-INVALID", "PKCE verifier is invalid")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class VerifiedAccessTokenClaims:
    """Claims returned only by a trusted signature verifier or introspection client."""

    issuer: str
    subject: str
    actor: str
    audience: str
    resource: str
    scopes: frozenset[str]
    expires_at_epoch: float


TokenClaimsVerifier = Callable[[str], VerifiedAccessTokenClaims]
ClientAuthenticationProvider = Callable[[], Mapping[str, str]]


class MCPAccessToken:
    """In-memory downstream bearer token provider with a deliberately redacted repr."""

    __slots__ = ("_access_token", "credential", "expires_at_epoch")

    def __init__(
        self,
        access_token: str,
        credential: CredentialClaims,
        expires_at_epoch: float,
    ) -> None:
        self._access_token = access_token
        self.credential = credential
        self.expires_at_epoch = expires_at_epoch

    def __repr__(self) -> str:
        return (
            "MCPAccessToken(access_token='[REDACTED]', "
            f"credential={self.credential!r}, expires_at_epoch={self.expires_at_epoch!r})"
        )

    def __call__(self) -> str:
        if time.time() >= self.expires_at_epoch:
            raise MCPOAuthError("MCP-OAUTH-TOKEN-EXPIRED", "downstream access token expired")
        return f"Bearer {self._access_token}"


class MCPAuthorizationCodeTokenClient:
    """Exchange one validated authorization code and bind verified token claims."""

    def __init__(
        self,
        discovery: MCPAuthorizationDiscovery,
        profile: OAuthSecurityProfile,
        *,
        expected_client_id: str,
        expected_actor: str,
        expected_audience: str | None = None,
        claims_verifier: TokenClaimsVerifier,
        client_authentication_provider: ClientAuthenticationProvider | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not expected_client_id or not expected_actor:
            raise ValueError("expected client and actor are required")
        self.discovery = discovery
        self.profile = profile
        self.expected_client_id = expected_client_id
        self.expected_actor = expected_actor
        self.expected_audience = expected_audience or discovery.protected_resource.resource
        self._claims_verifier = claims_verifier
        self._client_authentication_provider = client_authentication_provider
        handlers: list[Any] = [_NoRedirectHandler()]
        if ssl_context is not None:
            handlers.append(HTTPSHandler(context=ssl_context))
        self._opener = build_opener(*handlers)

    def exchange(
        self,
        transaction: OAuthAuthorizationTransaction,
        authorization_code: str,
    ) -> MCPAccessToken:
        if not transaction.callback_validated:
            raise MCPOAuthError("MCP-OAUTH-CALLBACK-NOT-VALIDATED", "validate the OAuth callback first")
        if transaction.exchange_consumed:
            raise MCPOAuthError("MCP-OAUTH-CODE-REPLAY", "authorization code transaction was already consumed")
        transaction.exchange_consumed = True
        if not authorization_code or "\r" in authorization_code or "\n" in authorization_code:
            raise MCPOAuthError("MCP-OAUTH-CODE-INVALID", "authorization code is invalid")
        code_digest = hashlib.sha256(authorization_code.encode("utf-8")).hexdigest()
        if (
            transaction.authorization_code_digest is None
            or not secrets.compare_digest(code_digest, transaction.authorization_code_digest)
        ):
            raise MCPOAuthError(
                "MCP-OAUTH-CODE-MISMATCH",
                "authorization code is not bound to the validated callback",
            )
        if transaction.client_id != self.expected_client_id:
            raise MCPOAuthError("MCP-OAUTH-CLIENT-ID-MISMATCH", "OAuth client ID does not match")
        if transaction.resource != self.discovery.protected_resource.resource:
            raise MCPOAuthError("MCP-OAUTH-RESOURCE-MISMATCH", "transaction resource does not match discovery")
        token_endpoint = validate_oauth_url(
            self.discovery.authorization_server.token_endpoint,
            allowed_hosts=self.profile.allowed_authorization_server_hosts,
            profile=self.profile,
            allow_query=True,
        )
        body = urlencode(
            {
                "grant_type": "authorization_code",
                "client_id": transaction.client_id,
                "code": authorization_code,
                "redirect_uri": transaction.redirect_uri,
                "code_verifier": transaction.code_verifier,
                "resource": transaction.resource,
            }
        ).encode("ascii")
        headers = {
            "Accept": "application/json",
            "Cache-Control": "no-store",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if self._client_authentication_provider is not None:
            try:
                client_headers = self._client_authentication_provider()
            except Exception:
                raise MCPOAuthError(
                    "MCP-OAUTH-CLIENT-AUTH-FAILED",
                    "client authentication provider failed",
                ) from None
            if not isinstance(client_headers, Mapping):
                raise MCPOAuthError(
                    "MCP-OAUTH-CLIENT-AUTH-INVALID",
                    "client authentication provider must return headers",
                )
            for key, value in client_headers.items():
                if key.casefold() != "authorization":
                    raise MCPOAuthError(
                        "MCP-OAUTH-CLIENT-AUTH-INVALID",
                        "client authentication provider returned an unsupported header",
                    )
                if not _safe_header_value(value):
                    raise MCPOAuthError("MCP-OAUTH-CLIENT-AUTH-INVALID", "client authentication header is invalid")
                headers[key] = value
        request = Request(token_endpoint, data=body, method="POST", headers=headers)
        try:
            response = self._opener.open(request, timeout=self.profile.timeout_seconds)
        except HTTPError as error:
            status = error.code
            error.close()
            if status in _REDIRECT_STATUSES:
                raise MCPOAuthError("MCP-OAUTH-TOKEN-REDIRECT-DENIED", "token endpoint redirect is forbidden") from None
            raise MCPOAuthHTTPStatusError(status, reason_code="MCP-OAUTH-TOKEN-STATUS") from None
        except (URLError, TimeoutError, OSError):
            raise MCPOAuthError("MCP-OAUTH-TOKEN-CONNECTION-FAILED", "token exchange failed") from None
        try:
            if response.status != 200:
                raise MCPOAuthHTTPStatusError(response.status, reason_code="MCP-OAUTH-TOKEN-STATUS")
            if _media_type(response.headers.get("Content-Type")) != "application/json":
                raise MCPOAuthError("MCP-OAUTH-CONTENT-TYPE-INVALID", "token response must be JSON")
            payload = response.read(self.profile.max_response_bytes + 1)
            if len(payload) > self.profile.max_response_bytes:
                raise MCPOAuthError("MCP-OAUTH-RESPONSE-TOO-LARGE", "token response is too large")
        finally:
            response.close()
        value = _json_mapping(payload)
        access_token = _required_string(value, "access_token", "MCP-OAUTH-TOKEN-RESPONSE-INVALID")
        if not _BEARER_TOKEN_RE.fullmatch(access_token):
            raise MCPOAuthError("MCP-OAUTH-TOKEN-RESPONSE-INVALID", "access token is not a valid Bearer token")
        if str(value.get("token_type", "")).casefold() != "bearer":
            raise MCPOAuthError("MCP-OAUTH-TOKEN-TYPE-INVALID", "token type must be Bearer")
        expires_in = value.get("expires_in")
        if expires_in is not None and (
            not isinstance(expires_in, int) or isinstance(expires_in, bool) or expires_in <= 0
        ):
            raise MCPOAuthError("MCP-OAUTH-TOKEN-RESPONSE-INVALID", "expires_in must be a positive integer")
        response_scopes = _parse_scope(value.get("scope", "")) if value.get("scope") else transaction.scopes
        try:
            verified = self._claims_verifier(access_token)
        except Exception:
            raise MCPOAuthError(
                "MCP-OAUTH-TOKEN-VERIFICATION-FAILED",
                "trusted access token verification failed",
            ) from None
        self._validate_verified_claims(verified, transaction, response_scopes)
        fingerprint = hashlib.sha256(access_token.encode("ascii")).hexdigest()
        credential = CredentialClaims(
            reference=f"oauth:{fingerprint[:16]}",
            issuer=verified.issuer,
            subject=verified.subject,
            actor=verified.actor,
            audience=verified.audience,
            resource=verified.resource,
            scopes=verified.scopes,
            delegation_depth=0,
            exchanged=True,
            fingerprint=f"sha256:{fingerprint}",
        )
        return MCPAccessToken(access_token, credential, verified.expires_at_epoch)

    def _validate_verified_claims(
        self,
        verified: VerifiedAccessTokenClaims,
        transaction: OAuthAuthorizationTransaction,
        response_scopes: tuple[str, ...],
    ) -> None:
        if not isinstance(verified, VerifiedAccessTokenClaims):
            raise MCPOAuthError(
                "MCP-OAUTH-TOKEN-VERIFICATION-INVALID",
                "token verifier returned an invalid result",
            )
        expected_issuer = self.discovery.authorization_server.issuer
        if verified.issuer != expected_issuer:
            raise MCPOAuthError("MCP-OAUTH-TOKEN-ISSUER-MISMATCH", "verified token issuer does not match")
        if verified.audience != self.expected_audience or verified.resource != transaction.resource:
            raise MCPOAuthError(
                "L1-M5-TOKEN-AUDIENCE-MISMATCH",
                "verified token audience or resource does not match the MCP server",
            )
        if verified.actor != self.expected_actor:
            raise MCPOAuthError("L1-M5-TOKEN-ACTOR-MISMATCH", "verified token actor does not match")
        if not verified.subject:
            raise MCPOAuthError("MCP-OAUTH-TOKEN-SUBJECT-MISSING", "verified token subject is missing")
        if verified.expires_at_epoch <= time.time():
            raise MCPOAuthError("MCP-OAUTH-TOKEN-EXPIRED", "verified access token is expired")
        requested = set(transaction.scopes)
        if not requested.issubset(verified.scopes) or set(response_scopes) != set(verified.scopes):
            raise MCPOAuthError("MCP-OAUTH-TOKEN-SCOPE-MISMATCH", "verified token scopes do not match")


def validate_oauth_url(
    value: str,
    *,
    allowed_hosts: frozenset[str],
    profile: OAuthSecurityProfile,
    allow_query: bool,
) -> str:
    """Validate a server-fetched OAuth URL against scheme, host, DNS, and SSRF policy."""
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise MCPOAuthError("MCP-OAUTH-URL-UNSAFE", "OAuth URL is invalid")
    if "\\" in value or any(ord(character) < 0x20 for character in value):
        raise MCPOAuthError("MCP-OAUTH-URL-UNSAFE", "OAuth URL contains unsafe characters")
    try:
        parsed = urlsplit(value)
        host = _canonical_host(parsed.hostname or "")
        port = parsed.port
    except (ValueError, UnicodeError) as error:
        raise MCPOAuthError("MCP-OAUTH-URL-UNSAFE", "OAuth URL is invalid") from error
    canonical_allowed = frozenset(_canonical_host(item) for item in allowed_hosts)
    if host not in canonical_allowed or parsed.username or parsed.password or parsed.fragment:
        raise MCPOAuthError("MCP-OAUTH-URL-UNSAFE", "OAuth URL is outside the configured trust boundary")
    if not allow_query and parsed.query:
        raise MCPOAuthError("MCP-OAUTH-URL-UNSAFE", "OAuth URL query is not allowed here")
    explicit_loopback = _is_loopback_host(host)
    if parsed.scheme.casefold() == "https":
        pass
    elif parsed.scheme.casefold() == "http" and profile.allow_loopback_http and explicit_loopback and port is not None:
        pass
    else:
        raise MCPOAuthError("MCP-OAUTH-URL-UNSAFE", "OAuth URL must use HTTPS")
    addresses = _resolve_addresses(host, port, resolve_dns=profile.resolve_dns)
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_loopback and profile.allow_loopback_http and explicit_loopback:
            continue
        if not ip.is_global:
            raise MCPOAuthError("MCP-OAUTH-SSRF-BLOCKED", "OAuth URL resolves to a non-public address")
    default_port = 443 if parsed.scheme.casefold() == "https" else 80
    host_value = f"[{host}]" if ":" in host else host
    netloc = host_value + (f":{port}" if port is not None and port != default_port else "")
    return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/", parsed.query, ""))


def _split_quoted_list(value: str) -> tuple[str, ...]:
    output: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif quoted and character == "\\":
            current.append(character)
            escaped = True
        elif character == '"':
            current.append(character)
            quoted = not quoted
        elif character == "," and not quoted:
            if not current or not "".join(current).strip():
                raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "WWW-Authenticate is malformed")
            output.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if quoted or escaped or not "".join(current).strip():
        raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "WWW-Authenticate is malformed")
    output.append("".join(current).strip())
    return tuple(output)


def _add_auth_parameter(
    current_scheme: str,
    segment: str,
    bearer_parameters: dict[str, str] | None,
) -> None:
    if current_scheme != "bearer" or bearer_parameters is None:
        return
    match = _AUTH_PARAM_RE.fullmatch(segment.strip())
    if match is None:
        raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "Bearer challenge parameter is malformed")
    name = match.group(1).casefold()
    if name in bearer_parameters:
        raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "Bearer challenge parameter is duplicated")
    bearer_parameters[name] = _unquote_auth_value(match.group(2).strip())


def _unquote_auth_value(value: str) -> str:
    if value.startswith('"'):
        if len(value) < 2 or not value.endswith('"'):
            raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "quoted challenge value is invalid")
        output: list[str] = []
        escaped = False
        for character in value[1:-1]:
            if escaped:
                output.append(character)
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"' or ord(character) < 0x20:
                raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "quoted challenge value is invalid")
            else:
                output.append(character)
        if escaped:
            raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "quoted challenge value is invalid")
        return "".join(output)
    if not _TOKEN_RE.fullmatch(value):
        raise MCPOAuthError("MCP-OAUTH-CHALLENGE-INVALID", "challenge value is invalid")
    return value


def _parse_scope(value: str) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise MCPOAuthError("MCP-OAUTH-SCOPE-INVALID", "OAuth scope is invalid")
    scopes = tuple(value.split(" ")) if value else ()
    if any(not item for item in scopes) or len(set(scopes)) != len(scopes):
        raise MCPOAuthError("MCP-OAUTH-SCOPE-INVALID", "OAuth scope is malformed")
    for scope in scopes:
        _validate_scope_token(scope)
    return scopes


def _validate_scope_token(value: str) -> None:
    if not isinstance(value, str) or not value or any(
        ord(character) < 0x21 or character in {'"', "\\"} for character in value
    ):
        raise MCPOAuthError("MCP-OAUTH-SCOPE-INVALID", "OAuth scope token is invalid")


def _canonical_host(value: str) -> str:
    host = value.strip().rstrip(".")
    if not host:
        raise ValueError("host is required")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return host.encode("idna").decode("ascii").casefold()
    return str(ip)


def _host_from_url(value: str) -> str:
    try:
        host = urlsplit(value).hostname
    except ValueError as error:
        raise MCPOAuthError("MCP-OAUTH-URL-UNSAFE", "OAuth URL is invalid") from error
    if not host:
        raise MCPOAuthError("MCP-OAUTH-URL-UNSAFE", "OAuth URL host is missing")
    return _canonical_host(host)


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _resolve_addresses(host: str, port: int | None, *, resolve_dns: bool) -> tuple[str, ...]:
    try:
        return (str(ipaddress.ip_address(host.strip("[]"))),)
    except ValueError:
        if not resolve_dns:
            return ()
    try:
        values = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    except OSError as error:
        raise MCPOAuthError("MCP-OAUTH-DNS-FAILED", "OAuth host DNS resolution failed") from error
    addresses = tuple(dict.fromkeys(item[4][0] for item in values))
    if not addresses:
        raise MCPOAuthError("MCP-OAUTH-DNS-FAILED", "OAuth host has no addresses")
    return addresses


def _origin(parsed) -> str:  # noqa: ANN001
    host = _canonical_host(parsed.hostname or "")
    host_value = f"[{host}]" if ":" in host else host
    default = 443 if parsed.scheme == "https" else 80
    port = f":{parsed.port}" if parsed.port and parsed.port != default else ""
    return f"{parsed.scheme}://{host_value}{port}"


def _required_string(value: Mapping[str, Any], key: str, reason_code: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise MCPOAuthError(reason_code, f"OAuth metadata field {key} is required")
    return item


def _string_array(
    value: Any,
    reason_code: str,
    *,
    required: bool = False,
) -> tuple[str, ...]:
    if value is None and not required:
        return ()
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise MCPOAuthError(reason_code, "OAuth metadata string array is invalid")
    if len(set(value)) != len(value):
        raise MCPOAuthError(reason_code, "OAuth metadata string array contains duplicates")
    return tuple(value)


def _media_type(value: str | None) -> str:
    return (value or "").split(";", 1)[0].strip().casefold()


def _json_mapping(payload: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MCPOAuthError("MCP-OAUTH-JSON-INVALID", "OAuth response is not valid JSON") from error
    if isinstance(value, list) or not isinstance(value, Mapping):
        raise MCPOAuthError("MCP-OAUTH-JSON-INVALID", "OAuth response must be a JSON object")
    return dict(value)


def _validate_redirect_uri(value: str, *, allow_loopback_http: bool) -> None:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise MCPOAuthError("MCP-OAUTH-REDIRECT-URI-INVALID", "redirect URI is invalid") from error
    if not host or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise MCPOAuthError("MCP-OAUTH-REDIRECT-URI-INVALID", "redirect URI must be exact and query-free")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and allow_loopback_http and _is_loopback_host(host) and port is not None:
        return
    raise MCPOAuthError("MCP-OAUTH-REDIRECT-URI-INVALID", "redirect URI must use HTTPS")


def _append_oauth_query(endpoint: str, parameters: Mapping[str, str]) -> str:
    parsed = urlsplit(endpoint)
    existing = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    protected_names = set(parameters)
    if any(name in protected_names for name, _ in existing):
        raise MCPOAuthError("MCP-OAUTH-AUTHORIZATION-ENDPOINT-INVALID", "authorization endpoint overrides OAuth parameters")
    query = urlencode([*existing, *parameters.items()])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _unique_query_parameters(query: str) -> dict[str, str]:
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
    except ValueError as error:
        raise MCPOAuthError("MCP-OAUTH-CALLBACK-INVALID", "OAuth callback query is malformed") from error
    output: dict[str, str] = {}
    for key, value in pairs:
        if key in output:
            raise MCPOAuthError("MCP-OAUTH-CALLBACK-INVALID", "OAuth callback parameter is duplicated")
        output[key] = value
    return output


def _safe_header_value(value: str) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 8192 and "\r" not in value and "\n" not in value
