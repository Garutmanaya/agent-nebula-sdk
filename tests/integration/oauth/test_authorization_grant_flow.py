"""Integration tests for the RFC 7523 JWT bearer authorization-grant role."""

from __future__ import annotations

from agent_nebula_sdk.oauth.rfc7523 import (
    InMemoryAssertionReplayStore,
    InMemoryAuthorizationGrantKeyResolver,
    JwtAssertionValidator,
    JwtAuthorizationGrantBuilder,
    JwtAuthorizationGrantValidator,
    PrivateKeyJwtSigningKey,
    Rfc7523Policy,
)
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_rsa_key_pair

TOKEN_ENDPOINT = "https://nebula.example/oauth/token"


def test_authorization_grant_round_trip() -> None:
    """An issuer-created JWT grant is independently verified by the authorization server."""
    private_key, public_jwk = build_rsa_key_pair()
    clock = FixedClock()
    policy = Rfc7523Policy()
    builder = JwtAuthorizationGrantBuilder(
        clock=clock,
        policy=policy,
        assertion_id_factory=lambda: "grant-123",
    )
    keys = InMemoryAuthorizationGrantKeyResolver()
    keys.put(issuer="https://issuer.example", key=public_jwk)
    validator = JwtAuthorizationGrantValidator(
        keys=keys,
        replay_store=InMemoryAssertionReplayStore(clock=clock),
        validator=JwtAssertionValidator(clock=clock, policy=policy),
        accepted_audiences=(TOKEN_ENDPOINT,),
    )
    request = builder.build(
        issuer="https://issuer.example",
        subject="user-123",
        audience=TOKEN_ENDPOINT,
        signing_key=PrivateKeyJwtSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=private_key,
        ),
        additional_claims={"tenant": "example"},
    )

    result = validator.validate(request)

    assert result.issuer == "https://issuer.example"
    assert result.subject == "user-123"
    assert result.claims["tenant"] == "example"
