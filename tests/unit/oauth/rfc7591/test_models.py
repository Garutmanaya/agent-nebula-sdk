"""Unit tests for RFC 7591 client metadata validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata


def test_private_key_jwt_accepts_inline_jwks(rsa_public_jwk: dict[str, str]) -> None:
    """Private-key JWT registration may carry an inline public JWK Set."""
    metadata = ClientMetadata.model_validate(
        {
            "client_name": "Parking Host",
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "jwks": {"keys": [rsa_public_jwk]},
            "agent_nebula_entity_type": "service_client",
        }
    )
    assert metadata.jwks is not None
    assert metadata.model_extra == {"agent_nebula_entity_type": "service_client"}
    assert "agent_nebula_entity_type" not in metadata.standard_metadata()
    assert (
        metadata.standard_metadata(allowed_extension_names=frozenset({"agent_nebula_entity_type"}))[
            "agent_nebula_entity_type"
        ]
        == "service_client"
    )


def test_jwks_uri_and_inline_jwks_are_mutually_exclusive(
    rsa_public_jwk: dict[str, str],
) -> None:
    """RFC 7591 prohibits sending both public-key metadata mechanisms."""
    with pytest.raises(ValidationError, match="mutually exclusive"):
        ClientMetadata.model_validate(
            {
                "token_endpoint_auth_method": "private_key_jwt",
                "grant_types": ["client_credentials"],
                "response_types": [],
                "jwks_uri": "https://client.example/.well-known/jwks.json",
                "jwks": {"keys": [rsa_public_jwk]},
            }
        )


def test_private_key_jwt_requires_public_key_metadata() -> None:
    """The registered authentication method must have a verification key source."""
    with pytest.raises(ValidationError, match="requires jwks_uri"):
        ClientMetadata.model_validate(
            {
                "token_endpoint_auth_method": "private_key_jwt",
                "grant_types": ["client_credentials"],
                "response_types": [],
            }
        )


def test_default_redirect_flow_requires_redirect_uri() -> None:
    """Omitted grant metadata defaults to authorization code and needs a redirect URI."""
    with pytest.raises(ValidationError, match="redirect_uris are required"):
        ClientMetadata(client_name="Redirect Client")


def test_machine_client_does_not_require_redirect_uri(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Client credentials registrations do not use browser redirect URIs."""
    metadata = ClientMetadata.model_validate(
        {
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "jwks": {"keys": [rsa_public_jwk]},
        }
    )
    assert metadata.redirect_uris == ()


def test_redirect_uri_rejects_fragment() -> None:
    """OAuth redirect URIs cannot contain fragment components."""
    with pytest.raises(ValidationError, match="must not contain a fragment"):
        ClientMetadata.model_validate(
            {
                "redirect_uris": ["https://client.example/callback#fragment"],
            }
        )


def test_metadata_uri_requires_absolute_uri() -> None:
    """Metadata URLs must be absolute so clients cannot publish ambiguous references."""
    with pytest.raises(ValidationError, match="URI must be absolute"):
        ClientMetadata.model_validate(
            {
                "redirect_uris": ["https://client.example/callback"],
                "client_uri": "/relative",
            }
        )


def test_http_metadata_uri_requires_authority() -> None:
    """HTTP metadata URLs require a host authority."""
    with pytest.raises(ValidationError, match="must include an authority"):
        ClientMetadata.model_validate(
            {
                "redirect_uris": ["https://client.example/callback"],
                "client_uri": "https:/missing-host",
            }
        )


def test_grant_and_response_types_must_be_consistent() -> None:
    """RFC 7591 Section 2.1 rejects inconsistent OAuth flow metadata."""
    with pytest.raises(ValidationError, match="authorization_code grant requires code"):
        ClientMetadata.model_validate(
            {
                "grant_types": ["authorization_code"],
                "response_types": [],
                "redirect_uris": ["https://client.example/callback"],
            }
        )
