"""Unit tests for MCP OAuth authorization discovery."""

from __future__ import annotations

from unittest.mock import Mock

from agent_nebula_sdk.mcp import McpAuthorizationDiscoveryClient
from agent_nebula_sdk.metadata import AuthorizationServerMetadata, ProtectedResourceMetadata


def test_discovery_uses_challenge_metadata_and_authoritative_scope() -> None:
    """Prefer the resource_metadata URL and scope supplied by a 401 challenge."""
    metadata_client = Mock()
    metadata_client.fetch_protected_resource.return_value = ProtectedResourceMetadata(
        resource="https://mcp.example.com/mcp",
        authorization_servers=("https://nebula.example.com",),
    )
    metadata_client.fetch_authorization_server_for_mcp.return_value = AuthorizationServerMetadata(
        issuer="https://nebula.example.com",
        token_endpoint="https://nebula.example.com/oauth/token",
        response_types_supported=(),
        client_id_metadata_document_supported=True,
        code_challenge_methods_supported=("S256",),
    )
    discovery = McpAuthorizationDiscoveryClient(metadata_client=metadata_client).discover(
        resource="https://mcp.example.com/mcp",
        www_authenticate=(
            'Bearer resource_metadata="https://mcp.example.com/metadata", scope="files:read"'
        ),
    )
    metadata_client.fetch_protected_resource.assert_called_once_with(
        "https://mcp.example.com/mcp",
        metadata_url="https://mcp.example.com/metadata",
    )
    assert discovery.challenged_scopes == ("files:read",)
