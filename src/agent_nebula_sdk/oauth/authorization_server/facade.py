"""Authorization-server facade composing the Phase 1 OAuth security profile."""

from __future__ import annotations

from agent_nebula_sdk.oauth.authorization_server.models import (
    TokenIssuanceRequest,
    TokenIssuanceResult,
)
from agent_nebula_sdk.oauth.rfc7523 import PrivateKeyJwtAuthenticator
from agent_nebula_sdk.oauth.rfc7591 import (
    DynamicClientRegistrationService,
    RegistrationRequest,
    RegistrationResponse,
)
from agent_nebula_sdk.oauth.rfc7592 import (
    ClientConfigurationResponse,
    ClientRegistrationManagementService,
    ClientUpdateRequest,
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
    RFC 7523, RFC 7591, RFC 7592, RFC 8707, RFC 9068, and RFC 9449.
    """

    def __init__(
        self,
        *,
        registration_service: DynamicClientRegistrationService,
        client_authenticator: PrivateKeyJwtAuthenticator,
        resource_service: ResourceResolutionService,
        token_issuer: JwtAccessTokenIssuer,
        dpop_validator: DpopProofValidator,
        registration_management_service: ClientRegistrationManagementService | None = None,
    ) -> None:
        """Inject independently replaceable protocol services."""
        self._registration_service = registration_service
        self._client_authenticator = client_authenticator
        self._resource_service = resource_service
        self._token_issuer = token_issuer
        self._dpop_validator = dpop_validator
        self._registration_management_service = registration_management_service

    def register_client(self, request: RegistrationRequest) -> RegistrationResponse:
        """Delegate one RFC 7591 registration operation."""
        return self._registration_service.register(request)

    def read_client_registration(
        self,
        *,
        client_id: str,
        registration_access_token: str,
    ) -> ClientConfigurationResponse:
        """Read an RFC 7592 client registration when management is configured."""
        service = self._require_registration_management_service()
        return service.read(
            client_id=client_id,
            registration_access_token=registration_access_token,
        )

    def update_client_registration(
        self,
        *,
        request: ClientUpdateRequest,
        registration_access_token: str,
    ) -> ClientConfigurationResponse:
        """Replace an RFC 7592 client registration when management is configured."""
        service = self._require_registration_management_service()
        return service.update(
            request=request,
            registration_access_token=registration_access_token,
        )

    def delete_client_registration(
        self,
        *,
        client_id: str,
        registration_access_token: str,
    ) -> None:
        """Delete an RFC 7592 client registration when management is configured."""
        service = self._require_registration_management_service()
        service.delete(
            client_id=client_id,
            registration_access_token=registration_access_token,
        )

    def _require_registration_management_service(self) -> ClientRegistrationManagementService:
        """Return the configured RFC 7592 service or fail with a clear composition error."""
        if self._registration_management_service is None:
            raise RuntimeError("registration_management_service is not configured")
        return self._registration_management_service

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
