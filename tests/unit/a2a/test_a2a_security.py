"""Unit tests for A2A Agent Card security declarations."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.a2a import A2ASecurityProfileBuilder, A2ASecurityProfileValidator
from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.metadata import AuthorizationServerMetadata, ProtectedResourceMetadata


def build_metadata() -> tuple[AuthorizationServerMetadata, ProtectedResourceMetadata]:
    """Create compatible authorization-server and resource metadata fixtures."""
    authorization_server = AuthorizationServerMetadata(
        issuer="https://nebula.example.com",
        token_endpoint="https://nebula.example.com/oauth/token",
        response_types_supported=(),
        grant_types_supported=("client_credentials",),
    )
    resource = ProtectedResourceMetadata(
        resource="https://metro.example.com/a2a",
        authorization_servers=("https://nebula.example.com",),
        dpop_signing_alg_values_supported=("ES256",),
        dpop_bound_access_tokens_required=True,
    )
    return authorization_server, resource


def test_builder_creates_active_oauth2_agent_card_scheme() -> None:
    """Build a standard A2A OAuth2 declaration without embedding credentials."""
    authorization_server, resource = build_metadata()
    profile = A2ASecurityProfileBuilder().build(
        authorization_server=authorization_server,
        protected_resource=resource,
    )
    A2ASecurityProfileValidator().validate(profile, scheme_name="nebula_oauth")
    scheme = profile.security_schemes["nebula_oauth"].oauth2_security_scheme
    assert scheme is not None
    assert scheme.flows.client_credentials is not None
    assert scheme.flows.client_credentials.token_url.endswith("/oauth/token")


def test_builder_rejects_unadvertised_authorization_server() -> None:
    """Reject an authorization server not trusted by the protected resource."""
    authorization_server, resource = build_metadata()
    resource = resource.model_copy(update={"authorization_servers": ("https://other.example.com",)})
    with pytest.raises(ProtocolValidationError) as exc_info:
        A2ASecurityProfileBuilder().build(
            authorization_server=authorization_server,
            protected_resource=resource,
        )
    assert exc_info.value.code == "authorization_server_not_allowed"
