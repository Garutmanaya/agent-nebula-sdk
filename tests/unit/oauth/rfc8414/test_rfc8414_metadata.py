"""Unit tests for direct RFC 8414 SDK imports."""

from agent_nebula_sdk.oauth.rfc8414 import (
    AuthorizationServerMetadata,
    authorization_server_metadata_url,
)


def test_rfc8414_metadata_and_well_known_url_are_available_directly() -> None:
    """Validate direct RFC 8414 model and discovery helper usage."""
    metadata = AuthorizationServerMetadata(
        issuer="https://oauth.example.test",
        token_endpoint="https://oauth.example.test/token",
        registration_endpoint="https://oauth.example.test/register",
    )
    assert metadata.issuer == "https://oauth.example.test"
    assert (
        authorization_server_metadata_url(metadata.issuer)
        == "https://oauth.example.test/.well-known/oauth-authorization-server"
    )
