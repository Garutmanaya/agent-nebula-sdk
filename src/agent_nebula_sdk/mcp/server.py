"""Server-side MCP HTTP authentication and challenge adapters."""

from __future__ import annotations

from agent_nebula_sdk.core.errors import ClientAuthenticationError
from agent_nebula_sdk.oauth.resource_server import ResourceSecurityContext, ResourceServerFacade
from agent_nebula_sdk.oauth.rfc9449 import DpopHttpHeaderCodec
from agent_nebula_sdk.oauth.rfc9728 import OAuthChallengeCodec, ProtectedResourceMetadata


class McpRequestAuthenticator:
    """Authenticate protected MCP requests before tool-level authorization."""

    def __init__(
        self,
        *,
        resource_server: ResourceServerFacade,
        metadata: ProtectedResourceMetadata,
        challenge_codec: OAuthChallengeCodec | None = None,
        header_codec: DpopHttpHeaderCodec | None = None,
    ) -> None:
        """Inject validation services and the resource's published metadata."""
        self._resource_server = resource_server
        self._metadata = metadata
        self._challenge_codec = challenge_codec or OAuthChallengeCodec()
        self._header_codec = header_codec or DpopHttpHeaderCodec()

    def authenticate(
        self,
        *,
        headers: dict[str, str],
        http_method: str,
        target_uri: str,
        expected_issuer: str,
        nonce_context: str | None = None,
    ) -> ResourceSecurityContext:
        """Validate RFC 9068 and RFC 9449 credentials for one MCP request."""
        normalized = {name.lower(): value for name, value in headers.items()}
        authorization = normalized.get("authorization")
        proof = normalized.get("dpop")
        if authorization is None or proof is None:
            raise ClientAuthenticationError(
                "MCP request requires Authorization and DPoP headers",
                code="missing_mcp_credentials",
            )
        access_token = self._header_codec.parse_authorization_header(authorization)
        return self._resource_server.authenticate_request(
            access_token=access_token,
            dpop_proof=proof,
            http_method=http_method,
            target_uri=target_uri,
            expected_issuer=expected_issuer,
            nonce_context=nonce_context,
        )

    def build_unauthorized_headers(
        self,
        *,
        metadata_url: str,
        required_scopes: tuple[str, ...] = (),
        error: str | None = None,
    ) -> dict[str, str]:
        """Build the RFC 9728 challenge required by protected MCP servers."""
        challenge = self._challenge_codec.build(
            resource_metadata=metadata_url,
            scope=required_scopes,
            error=error,
            scheme="DPoP" if self._metadata.dpop_bound_access_tokens_required else "Bearer",
        )
        return {"WWW-Authenticate": challenge}
