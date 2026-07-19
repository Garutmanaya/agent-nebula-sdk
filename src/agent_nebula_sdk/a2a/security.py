"""A2A Agent Card security-profile generation and validation.

A2A relies on established web authentication schemes and requires clients to
obtain credentials out of band. This module maps the SDK's OAuth/DPoP profile
into the Agent Card's ``securitySchemes`` and ``security`` fields without
placing credentials in the card.
"""

from __future__ import annotations

from agent_nebula_sdk.a2a.models import (
    A2AClientCredentialsFlow,
    A2AOAuth2SecurityScheme,
    A2AOAuthFlows,
    A2ASecurityProfile,
    A2ASecurityScheme,
)
from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.metadata import AuthorizationServerMetadata, ProtectedResourceMetadata


class A2ASecurityProfileBuilder:
    """Build an OAuth2 security declaration for an A2A Agent Card.

    The builder deliberately advertises only stable OAuth information. DPoP is
    discovered from RFC 9728 protected-resource metadata instead of being
    encoded as a custom A2A credential type.
    """

    def build(
        self,
        *,
        authorization_server: AuthorizationServerMetadata,
        protected_resource: ProtectedResourceMetadata,
        scheme_name: str = "nebula_oauth",
        scopes: dict[str, str] | None = None,
    ) -> A2ASecurityProfile:
        """Create the Agent Card security fragment for client credentials."""
        if authorization_server.token_endpoint is None:
            raise ProtocolValidationError(
                "authorization server metadata has no token endpoint",
                code="missing_token_endpoint",
            )
        if authorization_server.issuer not in protected_resource.authorization_servers:
            raise ProtocolValidationError(
                "authorization server is not trusted by the protected resource",
                code="authorization_server_not_allowed",
            )
        scheme = A2ASecurityScheme(
            oauth2SecurityScheme=A2AOAuth2SecurityScheme(
                flows=A2AOAuthFlows(
                    clientCredentials=A2AClientCredentialsFlow(
                        tokenUrl=authorization_server.token_endpoint,
                        scopes=scopes or {},
                    )
                ),
                oauth2MetadataUrl=None,
                description=(
                    "OAuth 2.0 client credentials with RFC 8707 resource indicators, "
                    "RFC 9068 JWT access tokens, and RFC 9449 DPoP."
                ),
            )
        )
        return A2ASecurityProfile(
            securitySchemes={scheme_name: scheme},
            security=({scheme_name: tuple((scopes or {}).keys())},),
            resource=protected_resource.resource,
        )


class A2ASecurityProfileValidator:
    """Validate that an Agent Card security fragment supports this SDK profile."""

    def validate(self, profile: A2ASecurityProfile, *, scheme_name: str) -> None:
        """Require the named OAuth scheme and an active matching requirement."""
        scheme = profile.security_schemes.get(scheme_name)
        if scheme is None or scheme.oauth2_security_scheme is None:
            raise ProtocolValidationError(
                "A2A Agent Card does not declare the required OAuth scheme",
                code="unsupported_a2a_security_scheme",
            )
        if not any(scheme_name in requirement for requirement in profile.security):
            raise ProtocolValidationError(
                "A2A Agent Card does not activate the declared OAuth scheme",
                code="missing_a2a_security_requirement",
            )
