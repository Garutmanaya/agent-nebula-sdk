"""MCP authorization-server discovery using current OAuth requirements.

Current MCP authorization requires RFC 9728 protected-resource metadata for
locating candidate authorization servers. The client then validates RFC 8414
or OpenID Connect discovery metadata, Client ID Metadata Document support, and
PKCE S256 support before returning trusted endpoints to the application.
"""

from __future__ import annotations

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.mcp.models import McpAuthorizationDiscovery
from agent_nebula_sdk.oauth.rfc8414 import (
    AuthorizationServerMetadata,
    AuthorizationServerMetadataClient,
)
from agent_nebula_sdk.oauth.rfc9728 import (
    OAuthChallengeCodec,
    ProtectedResourceMetadataClient,
)


class McpAuthorizationDiscoveryClient:
    """Discover trusted OAuth endpoints for one protected MCP server.

    The default policy implements the current MCP profile used by Agent
    Nebula: Client ID Metadata Documents are required and no RFC 7591 fallback
    is performed inside this package. PKCE using S256 is also mandatory.
    """

    def __init__(
        self,
        *,
        protected_resource_client: ProtectedResourceMetadataClient,
        authorization_server_client: AuthorizationServerMetadataClient,
        challenge_codec: OAuthChallengeCodec | None = None,
        require_client_id_metadata_document: bool = True,
        require_pkce_s256: bool = True,
    ) -> None:
        """Inject RFC-specific metadata clients and current-profile requirements."""
        self._protected_resource_client = protected_resource_client
        self._authorization_server_client = authorization_server_client
        self._challenge_codec = challenge_codec or OAuthChallengeCodec()
        self._require_client_id_metadata_document = require_client_id_metadata_document
        self._require_pkce_s256 = require_pkce_s256

    def discover(
        self,
        *,
        resource: str,
        www_authenticate: str | None = None,
        preferred_issuer: str | None = None,
    ) -> McpAuthorizationDiscovery:
        """Discover RFC 9728 metadata and select one advertised issuer."""
        metadata_url: str | None = None
        challenged_scopes: tuple[str, ...] = ()
        if www_authenticate is not None:
            challenge = self._challenge_codec.parse(www_authenticate)
            metadata_url = challenge.resource_metadata
            challenged_scopes = challenge.scope
        resource_metadata = self._protected_resource_client.fetch(
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
        authorization_server = self._authorization_server_client.fetch_with_openid_fallback(issuer)
        self._validate_current_profile(authorization_server)
        return McpAuthorizationDiscovery(
            protected_resource=resource_metadata,
            authorization_server=authorization_server,
            challenged_scopes=challenged_scopes,
        )

    def _validate_current_profile(
        self,
        authorization_server: AuthorizationServerMetadata,
    ) -> None:
        """Require Client ID Metadata Documents and PKCE S256 when configured."""
        if (
            self._require_client_id_metadata_document
            and not authorization_server.client_id_metadata_document_supported
        ):
            raise ProtocolValidationError(
                "authorization server does not support Client ID Metadata Documents",
                code="client_id_metadata_document_not_supported",
            )
        if (
            self._require_pkce_s256
            and "S256" not in authorization_server.code_challenge_methods_supported
        ):
            raise ProtocolValidationError(
                "authorization server does not advertise PKCE S256 support",
                code="pkce_s256_not_supported",
            )
