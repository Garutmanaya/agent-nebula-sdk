"""Tests for current MCP authorization-server discovery behavior."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.mcp import McpAuthorizationDiscoveryClient
from agent_nebula_sdk.oauth.rfc8414 import (
    AuthorizationServerMetadata,
    AuthorizationServerMetadataClient,
)
from agent_nebula_sdk.oauth.rfc9728 import (
    ProtectedResourceMetadata,
    ProtectedResourceMetadataClient,
)
from agent_nebula_sdk.ports.http import HttpResponse


class OrderedTransport:
    """Return metadata responses in deterministic discovery order."""

    def __init__(self) -> None:
        """Create an empty request log."""
        self.urls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Return RFC 9728, RFC 8414 404, then OpenID metadata."""
        self.urls.append(url)
        if "oauth-protected-resource" in url:
            payload = {
                "resource": "https://mcp.example.com/mcp",
                "authorization_servers": ["https://auth.example.com/tenant"],
            }
            return HttpResponse(
                200,
                {"content-type": "application/json"},
                json.dumps(payload).encode(),
            )
        if "oauth-authorization-server" in url:
            return HttpResponse(404, {"content-type": "application/json"}, b"{}")
        payload = {
            "issuer": "https://auth.example.com/tenant",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "response_types_supported": ["code"],
            "client_id_metadata_document_supported": True,
            "code_challenge_methods_supported": ["S256"],
        }
        return HttpResponse(200, {"content-type": "application/json"}, json.dumps(payload).encode())

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResponse:
        """Reject unsupported POST use in discovery tests."""
        raise AssertionError(f"unexpected POST {url}")


def test_mcp_discovery_falls_back_to_openid_configuration() -> None:
    """Try RFC 8414 before OpenID Connect path insertion."""
    transport = OrderedTransport()
    discovery = McpAuthorizationDiscoveryClient(
        protected_resource_client=ProtectedResourceMetadataClient(transport=transport),
        authorization_server_client=AuthorizationServerMetadataClient(transport=transport),
    ).discover(resource="https://mcp.example.com/mcp")

    assert discovery.authorization_server.client_id_metadata_document_supported is True
    assert discovery.authorization_server.code_challenge_methods_supported == ("S256",)
    assert transport.urls[1].endswith("/.well-known/oauth-authorization-server/tenant")
    assert transport.urls[2].endswith("/.well-known/openid-configuration/tenant")


def test_client_id_metadata_runtime_plugin_registration() -> None:
    """Install and resolve the MCP metadata resolver through ProtocolRuntime."""
    from agent_nebula_sdk.mcp.client_id_metadata import (
        MCP_CLIENT_ID_METADATA_COMPONENT,
        ClientIdMetadataPolicy,
        ClientIdMetadataResolver,
        McpClientIdMetadataPlugin,
    )
    from agent_nebula_sdk.runtime import ProtocolRuntime

    resolver = ClientIdMetadataResolver(
        transport=OrderedTransport(),
        policy=ClientIdMetadataPolicy(dns_resolver=lambda _hostname: ["93.184.216.34"]),
    )
    runtime = ProtocolRuntime(plugins=(McpClientIdMetadataPlugin(resolver),))

    assert (
        runtime.registry.resolve(
            MCP_CLIENT_ID_METADATA_COMPONENT,
            ClientIdMetadataResolver,
        )
        is resolver
    )


def test_mcp_discovery_rejects_missing_current_profile_capabilities() -> None:
    """Fail when CIMD or PKCE S256 is not advertised by the authorization server."""
    protected_resource_client = Mock()
    authorization_server_client = Mock()
    protected_resource_client.fetch.return_value = ProtectedResourceMetadata(
        resource="https://mcp.example.com/mcp",
        authorization_servers=("https://auth.example.com",),
    )
    authorization_server_client.fetch_with_openid_fallback.return_value = (
        AuthorizationServerMetadata(
            issuer="https://auth.example.com",
            response_types_supported=("code",),
            code_challenge_methods_supported=("S256",),
        )
    )
    with pytest.raises(ProtocolValidationError) as cimd_error:
        McpAuthorizationDiscoveryClient(
            protected_resource_client=protected_resource_client,
            authorization_server_client=authorization_server_client,
        ).discover(resource="https://mcp.example.com/mcp")
    assert cimd_error.value.code == "client_id_metadata_document_not_supported"

    authorization_server_client.fetch_with_openid_fallback.return_value = (
        AuthorizationServerMetadata(
            issuer="https://auth.example.com",
            response_types_supported=("code",),
            client_id_metadata_document_supported=True,
        )
    )
    with pytest.raises(ProtocolValidationError) as pkce_error:
        McpAuthorizationDiscoveryClient(
            protected_resource_client=protected_resource_client,
            authorization_server_client=authorization_server_client,
        ).discover(resource="https://mcp.example.com/mcp")
    assert pkce_error.value.code == "pkce_s256_not_supported"
