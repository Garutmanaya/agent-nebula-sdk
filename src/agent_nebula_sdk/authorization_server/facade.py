"""Authorization-server facade composing the Phase 1 OAuth security profile."""

from __future__ import annotations

from agent_nebula_sdk.authorization_server.models import (
    TokenIssuanceRequest,
    TokenIssuanceResult,
)
from agent_nebula_sdk.oauth.rfc7523 import PrivateKeyJwtAuthenticator
from agent_nebula_sdk.oauth.rfc7591 import (
    DynamicClientRegistrationService,
    RegistrationRequest,
    RegistrationResponse,
)
from agent_nebula_sdk.oauth.rfc8707 import ResourceIndicatorRequest, ResourceResolutionService
from agent_nebula_sdk.oauth.rfc9068 import (
    AccessTokenIssueRequest,
    AccessTokenSigningKey,
    JwtAccessTokenIssuer,
)
from agent_nebula_sdk.oauth.rfc9449 import DpopProofValidator


class AuthorizationServerFacade:
    """Coordinate registration, authentication, targeting, DPoP, and issuance.

    Responsibility
    --------------
    Provide an application-facing workflow without owning HTTP routes,
    persistence, trust scoring, or signing-key storage.

    Standards
    ---------
    RFC 7523, RFC 7591, RFC 8707, RFC 9068, and RFC 9449.
    """

    def __init__(
        self,
        *,
        registration_service: DynamicClientRegistrationService,
        client_authenticator: PrivateKeyJwtAuthenticator,
        resource_service: ResourceResolutionService,
        token_issuer: JwtAccessTokenIssuer,
        dpop_validator: DpopProofValidator,
    ) -> None:
        """Inject independently replaceable protocol services."""
        self._registration_service = registration_service
        self._client_authenticator = client_authenticator
        self._resource_service = resource_service
        self._token_issuer = token_issuer
        self._dpop_validator = dpop_validator

    def register_client(self, request: RegistrationRequest) -> RegistrationResponse:
        """Delegate one RFC 7591 registration operation."""
        return self._registration_service.register(request)

    def issue_resource_token(
        self,
        *,
        request: TokenIssuanceRequest,
        signing_key: AccessTokenSigningKey,
    ) -> TokenIssuanceResult:
        """Authenticate a client and issue one audience-bound DPoP token.

        Validation order is intentional: client authentication and DPoP proof
        possession are established before resource resolution and token signing.
        """
        client = self._client_authenticator.authenticate(request.client_authentication)
        proof = self._dpop_validator.validate_token_request(
            request.dpop_proof,
            http_method="POST",
            target_uri=request.token_endpoint,
            nonce_context=request.nonce_context,
        )
        audience = self._resource_service.resolve_single_audience(
            ResourceIndicatorRequest(resources=(request.resource,)),
        )
        issued = self._token_issuer.issue(
            request=AccessTokenIssueRequest(
                issuer=request.issuer,
                subject=request.subject or client.client_id,
                audience=audience,
                client_id=client.client_id,
                scope=request.scope,
                confirmation_jkt=proof.key_thumbprint,
                additional_claims=request.additional_claims,
            ),
            signing_key=signing_key,
        )
        return TokenIssuanceResult(
            access_token=issued,
            client_id=client.client_id,
            audience=audience,
            dpop_proof=proof,
        )
