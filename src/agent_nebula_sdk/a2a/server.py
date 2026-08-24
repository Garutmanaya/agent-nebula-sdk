"""Server-side A2A HTTP authentication adapter.

The adapter extracts OAuth credentials from HTTP headers and delegates all JWT,
audience, DPoP, nonce, and replay checks to the resource-server facade.
"""

from __future__ import annotations

from agent_nebula_sdk.core.errors import ClientAuthenticationError
from agent_nebula_sdk.oauth.resource_server import ResourceSecurityContext, ResourceServerFacade
from agent_nebula_sdk.oauth.rfc9449 import DpopHttpHeaderCodec


class A2ARequestAuthenticator:
    """Authenticate an incoming A2A HTTP request before local authorization."""

    def __init__(
        self,
        *,
        resource_server: ResourceServerFacade,
        header_codec: DpopHttpHeaderCodec | None = None,
    ) -> None:
        """Inject the resource-server role and standard DPoP header codec."""
        self._resource_server = resource_server
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
        """Validate Authorization and DPoP headers for one A2A request."""
        normalized = {name.lower(): value for name, value in headers.items()}
        authorization = normalized.get("authorization")
        proof = normalized.get("dpop")
        if authorization is None or proof is None:
            raise ClientAuthenticationError(
                "A2A request requires Authorization and DPoP headers",
                code="missing_a2a_credentials",
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
