"""Unit tests for MCP OAuth authorization discovery."""

from __future__ import annotations

from unittest.mock import Mock

from agent_nebula_sdk.mcp import McpAuthorizationDiscoveryClient
from agent_nebula_sdk.oauth.rfc8414 import AuthorizationServerMetadata
from agent_nebula_sdk.oauth.rfc9728 import ProtectedResourceMetadata


def test_discovery_uses_challenge_metadata_and_authoritative_scope() -> None:
    """Prefer the resource_metadata URL and scope supplied by a 401 challenge."""
    protected_resource_client = Mock()
    authorization_server_client = Mock()
    protected_resource_client.fetch.return_value = ProtectedResourceMetadata(
        resource="https://mcp.example.com/mcp",
        authorization_servers=("https://nebula.example.com",),
    )
    authorization_server_client.fetch_with_openid_fallback.return_value = (
        AuthorizationServerMetadata(
            issuer="https://nebula.example.com",
            token_endpoint="https://nebula.example.com/oauth/token",
            response_types_supported=(),
            client_id_metadata_document_supported=True,
            code_challenge_methods_supported=("S256",),
        )
    )
    discovery = McpAuthorizationDiscoveryClient(
        protected_resource_client=protected_resource_client,
        authorization_server_client=authorization_server_client,
    ).discover(
        resource="https://mcp.example.com/mcp",
        www_authenticate=(
            'Bearer resource_metadata="https://mcp.example.com/metadata", scope="files:read"'
        ),
    )
    protected_resource_client.fetch.assert_called_once_with(
        "https://mcp.example.com/mcp",
        metadata_url="https://mcp.example.com/metadata",
    )
    assert discovery.challenged_scopes == ("files:read",)
