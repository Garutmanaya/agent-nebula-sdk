"""Resource-server facade for RFC 9068 and RFC 9449 request validation."""

from __future__ import annotations

from agent_nebula_sdk.oauth.resource_server.models import ResourceSecurityContext
from agent_nebula_sdk.oauth.rfc8707 import ResourceAudienceValidator
from agent_nebula_sdk.oauth.rfc9068 import JwtAccessTokenValidator
from agent_nebula_sdk.oauth.rfc9449 import DpopProofValidator, DpopTokenBindingService


class ResourceServerFacade:
    """Validate a DPoP-bound access token before provider-local authorization.

    The facade establishes identity and proof-of-possession only. It does not
    decide whether a caller may execute a provider-specific A2A or MCP action.
    """

    def __init__(
        self,
        *,
        token_validator: JwtAccessTokenValidator,
        dpop_validator: DpopProofValidator,
        audience_validator: ResourceAudienceValidator,
        binding_service: DpopTokenBindingService | None = None,
    ) -> None:
        """Inject token, proof, audience, and confirmation-claim validators."""
        self._token_validator = token_validator
        self._dpop_validator = dpop_validator
        self._audience_validator = audience_validator
        self._binding_service = binding_service or DpopTokenBindingService()

    def authenticate_request(
        self,
        *,
        access_token: str,
        dpop_proof: str,
        http_method: str,
        target_uri: str,
        expected_issuer: str,
        nonce_context: str | None = None,
    ) -> ResourceSecurityContext:
        """Validate token, exact audience, DPoP binding, `ath`, and replay state."""
        token = self._token_validator.validate(
            access_token,
            expected_issuer=expected_issuer,
            expected_audiences=(self._audience_validator.expected_audience,),
        )
        self._audience_validator.validate(token.claims.audiences())
        key_thumbprint = self._binding_service.extract_key_thumbprint(
            token.claims.model_dump(exclude_none=True),
        )
        proof = self._dpop_validator.validate_resource_request(
            dpop_proof,
            http_method=http_method,
            target_uri=target_uri,
            access_token=access_token,
            expected_key_thumbprint=key_thumbprint,
            nonce_context=nonce_context,
        )
        return ResourceSecurityContext(
            subject=token.claims.sub,
            client_id=token.claims.client_id,
            claims=token.claims,
            dpop_proof=proof,
        )
