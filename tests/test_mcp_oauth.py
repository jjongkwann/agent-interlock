from __future__ import annotations

import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

from mcp_http_fixture import AdversarialMCPHTTPServer
from mcp_oauth_fixture import AdversarialOAuthServer

from agent_interlock import (
    MCPAuthorizationCodeFlow,
    MCPAuthorizationCodeTokenClient,
    MCPOAuthError,
    MCPProtectedResourceDiscovery,
    MCPStreamableHTTPClient,
    MCPStreamableHTTPClientConfig,
    OAuthSecurityProfile,
    VerifiedAccessTokenClaims,
    parse_bearer_challenge,
    pkce_s256_challenge,
    validate_oauth_url,
)


def security_profile(**overrides) -> OAuthSecurityProfile:
    values = {
        "allowed_authorization_server_hosts": frozenset({"127.0.0.1"}),
        "allow_loopback_http": True,
        "resolve_dns": False,
        "timeout_seconds": 1,
    }
    values.update(overrides)
    return OAuthSecurityProfile(**values)


def discover(server: AdversarialOAuthServer, challenge: str | None = None, **profile_overrides):
    profile = security_profile(**profile_overrides)
    result = MCPProtectedResourceDiscovery(server.endpoint, profile).discover(challenge)
    return profile, result


def verified_claims(server: AdversarialOAuthServer, *, actor: str = "agent.support", audience=None):
    return VerifiedAccessTokenClaims(
        issuer=server.issuer,
        subject="service-user-1",
        actor=actor,
        audience=audience or server.endpoint,
        resource=server.endpoint,
        scopes=frozenset({"mcp.read", "mcp.call"}),
        expires_at_epoch=time.time() + 300,
    )


def authorized_transaction(server: AdversarialOAuthServer):
    profile, result = discover(
        server,
        f'Bearer resource_metadata="{server.resource_metadata_url}", scope="mcp.read mcp.call"',
    )
    redirect_uri = "http://127.0.0.1:8765/callback"
    flow = MCPAuthorizationCodeFlow(
        result,
        profile,
        client_id="registered-client",
        registered_redirect_uris=frozenset({redirect_uri}),
        allow_loopback_http=True,
    )
    transaction = flow.begin(redirect_uri=redirect_uri)
    callback = f"{redirect_uri}?{urlencode({'code': 'one-time-code', 'state': transaction.state})}"
    code = flow.validate_callback(transaction, callback)
    return profile, result, transaction, code


class BearerChallengeTests(unittest.TestCase):
    def test_parses_mixed_challenges_and_authoritative_scope(self):
        challenge = parse_bearer_challenge(
            'Basic realm="legacy", Bearer resource_metadata='
            '"https://mcp.example/.well-known/oauth-protected-resource/mcp", '
            'scope="mcp.read mcp.call", error="insufficient_scope"'
        )
        self.assertEqual(challenge.scopes, ("mcp.read", "mcp.call"))
        self.assertEqual(challenge.error, "insufficient_scope")
        self.assertTrue(challenge.resource_metadata.endswith("/mcp"))

    def test_rejects_duplicate_or_header_injected_parameters(self):
        for value in (
            'Bearer scope="a", scope="b"',
            'Bearer scope="a\r\nX-Evil: yes"',
        ):
            with self.subTest(value=value), self.assertRaises(MCPOAuthError):
                parse_bearer_challenge(value)


class OAuthDiscoverySecurityTests(unittest.TestCase):
    def test_uses_protected_resource_path_and_official_issuer_path_order(self):
        with AdversarialOAuthServer() as server:
            _, result = discover(server)
            self.assertEqual(result.protected_resource.resource, server.endpoint)
            self.assertEqual(result.authorization_server.issuer, server.issuer)
            self.assertEqual(
                server.requested_paths[:2],
                [
                    "/.well-known/oauth-protected-resource/mcp",
                    "/.well-known/oauth-authorization-server/issuer",
                ],
            )

    def test_challenge_scope_is_preserved_for_authorization(self):
        with AdversarialOAuthServer() as server:
            profile, result = discover(
                server,
                f'Bearer resource_metadata="{server.resource_metadata_url}", scope="mcp.call"',
            )
            self.assertEqual(result.required_scopes, ("mcp.call",))

    def test_resource_issuer_and_pkce_metadata_fail_closed(self):
        with AdversarialOAuthServer() as server:
            server.resource_override = f"{server.base_url}/other-resource"
            with self.assertRaises(MCPOAuthError) as resource_error:
                discover(server)
            self.assertEqual(resource_error.exception.reason_code, "MCP-OAUTH-RESOURCE-MISMATCH")

            server.resource_override = None
            server.issuer_override = f"{server.base_url}/attacker"
            with self.assertRaises(MCPOAuthError) as issuer_error:
                discover(server)
            self.assertEqual(issuer_error.exception.reason_code, "MCP-OAUTH-ISSUER-MISMATCH")

            server.issuer_override = None
            server.pkce_methods = []
            with self.assertRaises(MCPOAuthError) as pkce_error:
                discover(server)
            self.assertEqual(pkce_error.exception.reason_code, "MCP-OAUTH-PKCE-S256-REQUIRED")

    def test_exact_issuer_allowlist_prevents_same_host_tenant_confusion(self):
        with AdversarialOAuthServer() as server:
            with self.assertRaises(MCPOAuthError) as issuer_error:
                discover(
                    server,
                    allowed_authorization_server_issuers=frozenset({f"{server.base_url}/other-tenant"}),
                )
            self.assertEqual(issuer_error.exception.reason_code, "MCP-OAUTH-ISSUER-NOT-ALLOWED")

    def test_ssrf_credentials_and_untrusted_redirect_are_blocked(self):
        profile = security_profile()
        for value, allowed in (
            ("https://169.254.169.254/latest/meta-data", frozenset({"169.254.169.254"})),
            ("https://user:password@127.0.0.1/token", frozenset({"127.0.0.1"})),
        ):
            with self.subTest(value=value), self.assertRaises(MCPOAuthError):
                validate_oauth_url(value, allowed_hosts=allowed, profile=profile, allow_query=True)

        with AdversarialOAuthServer() as server:
            server.metadata_redirect_location = "http://169.254.169.254/latest/meta-data"
            challenge = f'Bearer resource_metadata="{server.base_url}/redirect-metadata"'
            with self.assertRaises(MCPOAuthError) as redirect_error:
                discover(server, challenge, max_redirect_hops=1)
            self.assertEqual(redirect_error.exception.reason_code, "MCP-OAUTH-URL-UNSAFE")

    def test_redirects_are_disabled_by_default_and_validated_when_enabled(self):
        with AdversarialOAuthServer() as server:
            challenge = f'Bearer resource_metadata="{server.base_url}/redirect-metadata"'
            with self.assertRaises(MCPOAuthError) as denied:
                discover(server, challenge)
            self.assertEqual(denied.exception.reason_code, "MCP-OAUTH-REDIRECT-DENIED")

            server.requested_paths.clear()
            _, result = discover(server, challenge, max_redirect_hops=1)
            self.assertEqual(result.protected_resource.resource, server.endpoint)
            self.assertEqual(
                server.requested_paths[:2],
                ["/redirect-metadata", "/.well-known/oauth-protected-resource/mcp"],
            )


class AuthorizationCodeFlowTests(unittest.TestCase):
    def test_authorization_request_binds_resource_redirect_state_and_s256(self):
        with AdversarialOAuthServer() as server:
            profile, result = discover(
                server,
                f'Bearer resource_metadata="{server.resource_metadata_url}", scope="mcp.read mcp.call"',
            )
            redirect_uri = "http://127.0.0.1:8765/callback"
            flow = MCPAuthorizationCodeFlow(
                result,
                profile,
                client_id="registered-client",
                registered_redirect_uris=frozenset({redirect_uri}),
                allow_loopback_http=True,
            )
            transaction = flow.begin(redirect_uri=redirect_uri)
            parameters = parse_qs(urlsplit(transaction.authorization_uri).query)
            self.assertEqual(parameters["resource"], [server.endpoint])
            self.assertEqual(parameters["redirect_uri"], [redirect_uri])
            self.assertEqual(parameters["code_challenge_method"], ["S256"])
            self.assertEqual(parameters["code_challenge"], [pkce_s256_challenge(transaction.code_verifier)])
            self.assertNotIn(transaction.code_verifier, transaction.authorization_uri)
            self.assertNotIn(transaction.code_verifier, repr(transaction))
            self.assertNotIn(transaction.state, repr(transaction))

    def test_callback_is_exact_state_bound_and_one_time(self):
        with AdversarialOAuthServer() as server:
            profile, result = discover(server)
            redirect_uri = "http://127.0.0.1:8765/callback"
            flow = MCPAuthorizationCodeFlow(
                result,
                profile,
                client_id="registered-client",
                registered_redirect_uris=frozenset({redirect_uri}),
                allow_loopback_http=True,
            )
            transaction = flow.begin(redirect_uri=redirect_uri, scopes=("mcp.read",))
            with self.assertRaises(MCPOAuthError) as mismatch:
                flow.validate_callback(transaction, f"{redirect_uri}?code=x&state=attacker")
            self.assertEqual(mismatch.exception.reason_code, "MCP-OAUTH-STATE-MISMATCH")
            with self.assertRaises(MCPOAuthError) as replay:
                flow.validate_callback(
                    transaction,
                    f"{redirect_uri}?{urlencode({'code': 'x', 'state': transaction.state})}",
                )
            self.assertEqual(replay.exception.reason_code, "MCP-OAUTH-CALLBACK-REPLAY")


class TokenExchangeTests(unittest.TestCase):
    def test_exchange_sends_resource_pkce_and_exact_redirect_then_binds_claims(self):
        with AdversarialOAuthServer() as server:
            profile, result, transaction, code = authorized_transaction(server)
            token_client = MCPAuthorizationCodeTokenClient(
                result,
                profile,
                expected_client_id="registered-client",
                expected_actor="agent.support",
                claims_verifier=lambda token: verified_claims(server),
            )
            token = token_client.exchange(transaction, code)
            form = server.token_forms[0]
            self.assertEqual(form["resource"], [server.endpoint])
            self.assertEqual(form["redirect_uri"], [transaction.redirect_uri])
            self.assertEqual(form["code_verifier"], [transaction.code_verifier])
            self.assertEqual(form["code"], ["one-time-code"])
            self.assertEqual(token(), "Bearer downstream-token-secret")
            self.assertTrue(token.credential.exchanged)
            self.assertEqual(token.credential.resource, server.endpoint)
            self.assertNotIn(server.access_token, repr(token))
            self.assertNotIn(server.access_token, repr(token.credential))

    def test_token_exchange_is_bound_to_validated_code_and_registered_client(self):
        with AdversarialOAuthServer() as server:
            profile, result, transaction, _ = authorized_transaction(server)
            client = MCPAuthorizationCodeTokenClient(
                result,
                profile,
                expected_client_id="registered-client",
                expected_actor="agent.support",
                claims_verifier=lambda token: verified_claims(server),
            )
            with self.assertRaises(MCPOAuthError) as code_mismatch:
                client.exchange(transaction, "substituted-code")
            self.assertEqual(code_mismatch.exception.reason_code, "MCP-OAUTH-CODE-MISMATCH")
            self.assertEqual(server.token_forms, [])

        with AdversarialOAuthServer() as server:
            profile, result, transaction, code = authorized_transaction(server)
            client = MCPAuthorizationCodeTokenClient(
                result,
                profile,
                expected_client_id="other-client",
                expected_actor="agent.support",
                claims_verifier=lambda token: verified_claims(server),
            )
            with self.assertRaises(MCPOAuthError) as client_mismatch:
                client.exchange(transaction, code)
            self.assertEqual(client_mismatch.exception.reason_code, "MCP-OAUTH-CLIENT-ID-MISMATCH")
            self.assertEqual(server.token_forms, [])

    def test_verified_audience_actor_and_scope_must_match(self):
        with AdversarialOAuthServer() as server:
            profile, result, transaction, code = authorized_transaction(server)
            client = MCPAuthorizationCodeTokenClient(
                result,
                profile,
                expected_client_id="registered-client",
                expected_actor="agent.support",
                claims_verifier=lambda token: verified_claims(server, audience="https://wrong.example/mcp"),
            )
            with self.assertRaises(MCPOAuthError) as mismatch:
                client.exchange(transaction, code)
            self.assertEqual(mismatch.exception.reason_code, "L1-M5-TOKEN-AUDIENCE-MISMATCH")

    def test_exchanged_token_is_the_only_token_sent_by_streamable_http_client(self):
        with AdversarialMCPHTTPServer() as mcp_server, AdversarialOAuthServer() as oauth_server:
            oauth_server.resource_override = mcp_server.endpoint
            profile = security_profile()
            challenge = f'Bearer resource_metadata="{oauth_server.resource_metadata_url}", scope="mcp.read mcp.call"'
            result = MCPProtectedResourceDiscovery(mcp_server.endpoint, profile).discover(challenge)
            redirect_uri = "http://127.0.0.1:8765/callback"
            flow = MCPAuthorizationCodeFlow(
                result,
                profile,
                client_id="registered-client",
                registered_redirect_uris=frozenset({redirect_uri}),
                allow_loopback_http=True,
            )
            transaction = flow.begin(redirect_uri=redirect_uri)
            callback = f"{redirect_uri}?{urlencode({'code': 'wire-code', 'state': transaction.state})}"
            code = flow.validate_callback(transaction, callback)
            token = MCPAuthorizationCodeTokenClient(
                result,
                profile,
                expected_client_id="registered-client",
                expected_actor="agent.support",
                claims_verifier=lambda value: VerifiedAccessTokenClaims(
                    issuer=oauth_server.issuer,
                    subject="service-user-1",
                    actor="agent.support",
                    audience=mcp_server.endpoint,
                    resource=mcp_server.endpoint,
                    scopes=frozenset({"mcp.read", "mcp.call"}),
                    expires_at_epoch=time.time() + 300,
                ),
            ).exchange(transaction, code)
            mcp_server.expected_authorization = "Bearer downstream-token-secret"
            client = MCPStreamableHTTPClient(
                MCPStreamableHTTPClientConfig(
                    endpoint=mcp_server.endpoint,
                    allow_loopback_http=True,
                ),
                authorization_provider=token,
            )
            client.initialize()
            self.assertTrue(
                all(value == "Bearer downstream-token-secret" for value in mcp_server.received_authorizations)
            )
            self.assertEqual(token.credential.resource, mcp_server.endpoint)
            client.close_session()

    def test_token_endpoint_redirect_and_code_replay_are_blocked(self):
        with AdversarialOAuthServer() as server:
            profile, result, transaction, code = authorized_transaction(server)
            server.token_redirect_location = f"{server.base_url}/other-token"
            client = MCPAuthorizationCodeTokenClient(
                result,
                profile,
                expected_client_id="registered-client",
                expected_actor="agent.support",
                claims_verifier=lambda token: verified_claims(server),
            )
            with self.assertRaises(MCPOAuthError) as redirect:
                client.exchange(transaction, code)
            self.assertEqual(redirect.exception.reason_code, "MCP-OAUTH-TOKEN-REDIRECT-DENIED")
            with self.assertRaises(MCPOAuthError) as replay:
                client.exchange(transaction, code)
            self.assertEqual(replay.exception.reason_code, "MCP-OAUTH-CODE-REPLAY")


if __name__ == "__main__":
    unittest.main()
