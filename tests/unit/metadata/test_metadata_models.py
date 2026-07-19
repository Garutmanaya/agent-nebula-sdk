"""Unit tests for RFC 8414 and RFC 9728 metadata models."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.metadata import AuthorizationServerMetadata, ProtectedResourceMetadata


def test_authorization_server_metadata_accepts_phase1_profile() -> None:
    """Accept the endpoints and capabilities used by the Phase 1 SDK."""
    metadata = AuthorizationServerMetadata(
        issuer="https://nebula.example.com",
        token_endpoint="https://nebula.example.com/oauth/token",
        jwks_uri="https://nebula.example.com/.well-known/jwks.json",
        registration_endpoint="https://nebula.example.com/oauth/register",
        response_types_supported=(),
        grant_types_supported=("client_credentials",),
        token_endpoint_auth_methods_supported=("private_key_jwt",),
        token_endpoint_auth_signing_alg_values_supported=("ES256",),
        dpop_signing_alg_values_supported=("ES256",),
    )
    assert metadata.token_endpoint.endswith("/oauth/token")


def test_authorization_server_metadata_rejects_none_algorithm() -> None:
    """Reject unsigned client-authentication assertions in metadata."""
    with pytest.raises(ValueError):
        AuthorizationServerMetadata(
            issuer="https://nebula.example.com",
            response_types_supported=(),
            token_endpoint_auth_signing_alg_values_supported=("none",),
        )


def test_protected_resource_metadata_requires_dpop_algorithms() -> None:
    """Require at least one proof algorithm when DPoP is mandatory."""
    with pytest.raises(ValueError):
        ProtectedResourceMetadata(
            resource="https://metro.example.com/a2a",
            authorization_servers=("https://nebula.example.com",),
            dpop_bound_access_tokens_required=True,
        )


def test_protected_resource_metadata_checks_resource_identity() -> None:
    """Reject metadata retrieved for a different resource identifier."""
    metadata = ProtectedResourceMetadata(
        resource="https://metro.example.com/a2a",
        authorization_servers=("https://nebula.example.com",),
    )
    with pytest.raises(ProtocolValidationError) as exc_info:
        metadata.validate_for_requested_resource("https://airport.example.com/a2a")
    assert exc_info.value.code == "resource_metadata_mismatch"


def test_metadata_rejects_insecure_urls_and_none_resource_algorithm() -> None:
    """Reject insecure metadata references and unsigned resource responses."""
    with pytest.raises(ValueError):
        ProtectedResourceMetadata(resource="http://resource.example.com")
    with pytest.raises(ValueError):
        ProtectedResourceMetadata(
            resource="https://resource.example.com",
            resource_signing_alg_values_supported=("none",),
        )
