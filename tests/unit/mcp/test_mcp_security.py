"""Unit tests for MCP HTTP security adapters."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from agent_nebula_sdk.mcp import McpHttpSecurityClient, McpRequestAuthenticator
from agent_nebula_sdk.metadata import ProtectedResourceMetadata


def test_mcp_client_sets_protocol_and_session_headers() -> None:
    """Preserve MCP transport headers alongside DPoP credentials."""
    oauth = Mock()
    oauth.build_protected_request.return_value = SimpleNamespace(
        headers={"Authorization": "DPoP token", "DPoP": "proof"}
    )
    client = McpHttpSecurityClient(oauth=oauth, transport=Mock())
    request = client.build_request(
        endpoint="https://mcp.example.com/mcp",
        access_token="token",
        dpop_key=Mock(),
        payload={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        protocol_version="2025-11-25",
        session_id="session-1",
    )
    assert request.headers["MCP-Protocol-Version"] == "2025-11-25"
    assert request.headers["Mcp-Session-Id"] == "session-1"


def test_mcp_server_builds_rfc9728_challenge() -> None:
    """Advertise protected-resource metadata in an unauthorized response."""
    metadata = ProtectedResourceMetadata(
        resource="https://mcp.example.com/mcp",
        authorization_servers=("https://nebula.example.com",),
        dpop_signing_alg_values_supported=("ES256",),
        dpop_bound_access_tokens_required=True,
    )
    authenticator = McpRequestAuthenticator(resource_server=Mock(), metadata=metadata)
    headers = authenticator.build_unauthorized_headers(
        metadata_url="https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        required_scopes=("files:read",),
    )
    assert headers["WWW-Authenticate"].startswith("DPoP ")
    assert 'scope="files:read"' in headers["WWW-Authenticate"]


def test_mcp_server_authenticates_complete_dpop_headers() -> None:
    """Delegate complete MCP transport credentials to the resource-server role."""
    resource_server = Mock()
    resource_server.authenticate_request.return_value = object()
    metadata = ProtectedResourceMetadata(
        resource="https://mcp.example.com/mcp",
        authorization_servers=("https://nebula.example.com",),
    )
    authenticator = McpRequestAuthenticator(resource_server=resource_server, metadata=metadata)
    result = authenticator.authenticate(
        headers={"Authorization": "DPoP access-token", "DPoP": "proof"},
        http_method="POST",
        target_uri="https://mcp.example.com/mcp",
        expected_issuer="https://nebula.example.com",
    )
    assert result is resource_server.authenticate_request.return_value


def test_mcp_client_parses_json_response() -> None:
    """Parse JSON responses returned by protected MCP servers."""
    from agent_nebula_sdk.ports.http import HttpResponse

    transport = Mock()
    transport.post.return_value = HttpResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=b'{"jsonrpc":"2.0","result":{"tools":[]},"id":1}',
    )
    client = McpHttpSecurityClient(oauth=Mock(), transport=transport)
    response = client.send(
        SimpleNamespace(endpoint="https://mcp.example/mcp", headers={}, body=b"{}")
    )
    assert isinstance(response.payload, dict)
