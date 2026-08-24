"""Unit tests for direct RFC 9728 SDK imports."""

from agent_nebula_sdk.oauth.rfc9728 import (
    ProtectedResourceMetadata,
    protected_resource_metadata_urls,
)


def test_rfc9728_metadata_and_well_known_urls_are_available_directly() -> None:
    """Validate direct RFC 9728 metadata ownership and discovery helpers."""
    resource = "https://agents.example.test/travel"
    metadata = ProtectedResourceMetadata(
        resource=resource,
        authorization_servers=("https://oauth.example.test",),
        scopes_supported=("travel.search",),
    )
    metadata.validate_for_requested_resource(resource)
    assert protected_resource_metadata_urls(resource)[0].endswith(
        "/.well-known/oauth-protected-resource/travel"
    )
