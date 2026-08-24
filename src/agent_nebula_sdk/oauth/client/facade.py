"""Client-role facade composing RFC 7523, RFC 8707, and RFC 9449.

This facade is used by Host Agents and Provider Agents when they act as OAuth
clients. It only constructs protocol artifacts; transport and private-key
storage remain owned by the consuming application.
"""

from __future__ import annotations

from agent_nebula_sdk.oauth.client.models import (
    ClientTokenRequest,
    ProtectedRequestArtifacts,
    TokenRequestArtifacts,
)
from agent_nebula_sdk.oauth.rfc7523 import ClientAssertionBuilder, PrivateKeyJwtSigningKey
from agent_nebula_sdk.oauth.rfc7591 import (
    ClientMetadata,
    DynamicClientRegistrationClient,
    RegistrationResponse,
)
from agent_nebula_sdk.oauth.rfc7592 import (
    ClientConfigurationResponse,
    ClientRegistrationManagementClient,
    ClientUpdateRequest,
)
from agent_nebula_sdk.oauth.rfc8707 import ResourceParameterCodec
from agent_nebula_sdk.oauth.rfc9449 import (
    DpopHttpHeaderCodec,
    DpopProofBuilder,
    DpopProofBuildRequest,
    DpopSigningKey,
)


class OAuthClientFacade:
    """Expose stable client workflows while preserving RFC-specific components.

    Responsibility
    --------------
    Build registration requests, private-key JWT authentication, resource
    indicators, DPoP token-request proofs, and DPoP protected-resource headers.

    Standards
    ---------
    RFC 7523, RFC 7591, RFC 7592, RFC 8707, and RFC 9449.
    """

    def __init__(
        self,
        *,
        assertion_builder: ClientAssertionBuilder,
        resource_codec: ResourceParameterCodec,
        dpop_builder: DpopProofBuilder,
        header_codec: DpopHttpHeaderCodec | None = None,
        registration_client: DynamicClientRegistrationClient | None = None,
        registration_management_client: ClientRegistrationManagementClient | None = None,
    ) -> None:
        """Inject protocol components without constructing infrastructure implicitly."""
        self._assertion_builder = assertion_builder
        self._resource_codec = resource_codec
        self._dpop_builder = dpop_builder
        self._header_codec = header_codec or DpopHttpHeaderCodec()
        self._registration_client = registration_client
        self._registration_management_client = registration_management_client

    def register(
        self,
        metadata: ClientMetadata,
        *,
        initial_access_token: str | None = None,
    ) -> RegistrationResponse:
        """Register client metadata through RFC 7591 when a transport client is configured."""
        if self._registration_client is None:
            raise RuntimeError("registration_client is not configured")
        return self._registration_client.register(
            metadata,
            initial_access_token=initial_access_token,
        )

    def read_registration(self) -> ClientConfigurationResponse:
        """Read current client registration through RFC 7592 when configured."""
        if self._registration_management_client is None:
            raise RuntimeError("registration_management_client is not configured")
        return self._registration_management_client.read()

    def update_registration(
        self,
        request: ClientUpdateRequest,
    ) -> ClientConfigurationResponse:
        """Replace current client registration through RFC 7592 when configured."""
        if self._registration_management_client is None:
            raise RuntimeError("registration_management_client is not configured")
        return self._registration_management_client.update(request)

    def delete_registration(self) -> None:
        """Delete current client registration through RFC 7592 when configured."""
        if self._registration_management_client is None:
            raise RuntimeError("registration_management_client is not configured")
        self._registration_management_client.delete()

    def build_token_request(
        self,
        *,
        request: ClientTokenRequest,
        authentication_key: PrivateKeyJwtSigningKey,
        dpop_key: DpopSigningKey,
    ) -> TokenRequestArtifacts:
        """Build a client-credentials request with resource and DPoP proof.

        The method creates a fresh RFC 7523 assertion and RFC 9449 proof for
        every call. The returned dictionary is suitable for form encoding by
        an HTTP adapter; duplicate resource values remain representable.
        """
        authentication = self._assertion_builder.build(
            client_id=request.client_id,
            token_endpoint=request.token_endpoint,
            signing_key=authentication_key,
        )
        dpop_proof = self._dpop_builder.build(
            request=DpopProofBuildRequest(
                http_method="POST",
                target_uri=request.token_endpoint,
                nonce=request.nonce,
            ),
            signing_key=dpop_key,
        )
        fields: dict[str, str | tuple[str, ...]] = {
            "grant_type": "client_credentials",
            **authentication.to_form_fields(),
            "resource": request.resource,
        }
        if request.scope:
            fields["scope"] = " ".join(request.scope)
        return TokenRequestArtifacts(
            form_fields=fields,
            client_authentication=authentication,
            dpop_proof=dpop_proof,
        )

    def build_protected_request(
        self,
        *,
        http_method: str,
        target_uri: str,
        access_token: str,
        dpop_key: DpopSigningKey,
        nonce: str | None = None,
    ) -> ProtectedRequestArtifacts:
        """Build RFC 9449 headers for one protected-resource request."""
        proof = self._dpop_builder.build(
            request=DpopProofBuildRequest(
                http_method=http_method,
                target_uri=target_uri,
                access_token=access_token,
                nonce=nonce,
            ),
            signing_key=dpop_key,
        )
        headers = self._header_codec.build_request_headers(
            access_token=access_token,
            proof=proof.proof,
        ).as_dict()
        return ProtectedRequestArtifacts(headers=headers, dpop_proof=proof)
