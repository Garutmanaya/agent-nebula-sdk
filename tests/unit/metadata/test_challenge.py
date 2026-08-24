"""Unit tests for RFC 9728 WWW-Authenticate challenge handling."""

from __future__ import annotations

from agent_nebula_sdk.oauth.rfc9728 import OAuthChallengeCodec


def test_challenge_round_trip_preserves_resource_and_scopes() -> None:
    """Build and parse the challenge fields required by MCP clients."""
    codec = OAuthChallengeCodec()
    encoded = codec.build(
        resource_metadata="https://mcp.example/.well-known/oauth-protected-resource",
        scope=("files:read", "files:write"),
        error="invalid_token",
    )
    parsed = codec.parse(encoded)
    assert parsed.scheme == "DPoP"
    assert parsed.scope == ("files:read", "files:write")
    assert parsed.error == "invalid_token"


def test_challenge_rejects_unsupported_scheme() -> None:
    """Reject non-OAuth authentication schemes."""
    import pytest

    from agent_nebula_sdk.core.errors import ProtocolValidationError

    with pytest.raises(ProtocolValidationError):
        OAuthChallengeCodec().parse('Basic realm="example"')
