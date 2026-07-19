"""MCP authorization-server discovery using RFC 9728 and RFC 8414.

Current MCP authorization requires protected-resource metadata for locating
candidate authorization servers. This module validates that association before
returning discovery data to the client application.
"""

from __future__ import annotations

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.mcp.models import McpAuthorizationDiscovery
from agent_nebula_sdk.metadata import OAuthChallengeCodec, OAuthMetadataClient


class McpAuthorizationDiscoveryClient:
    """Discover trusted OAuth endpoints for one protected MCP server."""

    def __init__(
        self,
        *,
        metadata_client: OAuthMetadataClient,
        challenge_codec: OAuthChallengeCodec | None = None,
    ) -> None:
        """Inject shared OAuth metadata and challenge components."""
        self._metadata_client = metadata_client
        self._challenge_codec = challenge_codec or OAuthChallengeCodec()

    def discover(
        self,
        *,
        resource: str,
        www_authenticate: str | None = None,
        preferred_issuer: str | None = None,
    ) -> McpAuthorizationDiscovery:
        """Discover RFC 9728 metadata and select one advertised issuer.

        An explicit ``resource_metadata`` URL from a 401 challenge takes
        precedence over constructed well-known locations, as required by MCP.
        """
        metadata_url: str | None = None
        challenged_scopes: tuple[str, ...] = ()
        if www_authenticate is not None:
            challenge = self._challenge_codec.parse(www_authenticate)
            metadata_url = challenge.resource_metadata
            challenged_scopes = challenge.scope
        resource_metadata = self._metadata_client.fetch_protected_resource(
            resource,
            metadata_url=metadata_url,
        )
        if not resource_metadata.authorization_servers:
            raise ProtocolValidationError(
                "MCP protected resource metadata must advertise an authorization server",
                code="missing_authorization_server",
            )
        issuer = preferred_issuer or resource_metadata.authorization_servers[0]
        if issuer not in resource_metadata.authorization_servers:
            raise ProtocolValidationError(
                "preferred authorization server is not advertised by the MCP resource",
                code="authorization_server_not_allowed",
            )
        authorization_server = self._metadata_client.fetch_authorization_server(issuer)
        return McpAuthorizationDiscovery(
            protected_resource=resource_metadata,
            authorization_server=authorization_server,
            challenged_scopes=challenged_scopes,
        )
