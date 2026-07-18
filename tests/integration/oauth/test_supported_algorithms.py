"""Cross-algorithm RFC 7523 tests for RSA, EC, and Ed25519 client keys."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.oauth.rfc7523 import (
    ClientAssertionBuilder,
    InMemoryAssertionReplayStore,
    InMemoryClientKeyResolver,
    InMemoryRegisteredClient,
    InMemoryRegisteredClientStore,
    JwtAssertionValidator,
    PrivateKeyJwtAuthenticator,
    PrivateKeyJwtSigningKey,
    Rfc7523Policy,
)
from tests.unit.oauth.rfc7523.helpers import (
    FixedClock,
    build_ec_key_pair,
    build_ed25519_key_pair,
    build_rsa_key_pair,
)

TOKEN_ENDPOINT = "https://nebula.example/oauth/token"


@pytest.mark.parametrize(
    ("algorithm", "key_factory"),
    [
        ("RS256", build_rsa_key_pair),
        ("ES256", build_ec_key_pair),
        ("EdDSA", build_ed25519_key_pair),
    ],
)
def test_supported_asymmetric_algorithm_round_trip(algorithm: str, key_factory: object) -> None:
    """Each Phase 1 asymmetric algorithm signs and verifies a client assertion."""
    factory = key_factory
    private_key, public_jwk = factory()  # type: ignore[operator]
    clock = FixedClock()
    policy = Rfc7523Policy()
    clients = InMemoryRegisteredClientStore((InMemoryRegisteredClient(client_id="client"),))
    keys = InMemoryClientKeyResolver()
    keys.put(client_id="client", key=public_jwk)
    builder = ClientAssertionBuilder(clock=clock, policy=policy)
    request = builder.build(
        client_id="client",
        token_endpoint=TOKEN_ENDPOINT,
        signing_key=PrivateKeyJwtSigningKey(
            key_id=public_jwk.kid or "missing",
            algorithm=algorithm,
            private_key=private_key,
        ),
    )
    authenticator = PrivateKeyJwtAuthenticator(
        clients=clients,
        keys=keys,
        replay_store=InMemoryAssertionReplayStore(clock=clock),
        validator=JwtAssertionValidator(clock=clock, policy=policy),
        accepted_audiences=(TOKEN_ENDPOINT,),
    )

    result = authenticator.authenticate(request)

    assert result.algorithm == algorithm
