"""Cross-role integration tests for RFC 7523 private-key JWT authentication."""

from __future__ import annotations

from datetime import timedelta

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
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
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_rsa_key_pair

TOKEN_ENDPOINT = "https://nebula.example/oauth/token"


def build_flow() -> tuple[
    ClientAssertionBuilder, PrivateKeyJwtAuthenticator, PrivateKeyJwtSigningKey
]:
    """Compose client and authorization-server roles using only SDK public APIs."""
    private_key, public_jwk = build_rsa_key_pair()
    clock = FixedClock()
    policy = Rfc7523Policy(
        assertion_lifetime=timedelta(minutes=2),
        maximum_assertion_lifetime=timedelta(minutes=5),
    )
    clients = InMemoryRegisteredClientStore(
        (
            InMemoryRegisteredClient(
                client_id="parking-host",
                metadata={"registration_method": "open"},
            ),
        )
    )
    keys = InMemoryClientKeyResolver()
    keys.put(client_id="parking-host", key=public_jwk)
    authenticator = PrivateKeyJwtAuthenticator(
        clients=clients,
        keys=keys,
        replay_store=InMemoryAssertionReplayStore(clock=clock),
        validator=JwtAssertionValidator(clock=clock, policy=policy),
        accepted_audiences=(TOKEN_ENDPOINT,),
    )
    builder = ClientAssertionBuilder(
        clock=clock,
        policy=policy,
        assertion_id_factory=lambda: "assertion-123",
    )
    signing_key = PrivateKeyJwtSigningKey(
        key_id="rsa-client-2026-01",
        algorithm="RS256",
        private_key=private_key,
    )
    return builder, authenticator, signing_key


def test_client_authenticates_without_shared_secret() -> None:
    """A dynamically registered-style client proves possession of its private key."""
    builder, authenticator, signing_key = build_flow()
    request = builder.build(
        client_id="parking-host",
        token_endpoint=TOKEN_ENDPOINT,
        signing_key=signing_key,
    )

    authenticated = authenticator.authenticate(request)

    assert authenticated.client_id == "parking-host"
    assert authenticated.key_id == "rsa-client-2026-01"
    assert authenticated.algorithm == "RS256"
    assert authenticated.metadata == {"registration_method": "open"}


def test_replayed_assertion_is_rejected_atomically() -> None:
    """The same signed assertion cannot authenticate the client twice."""
    builder, authenticator, signing_key = build_flow()
    request = builder.build(
        client_id="parking-host",
        token_endpoint=TOKEN_ENDPOINT,
        signing_key=signing_key,
    )

    authenticator.authenticate(request)
    with pytest.raises(ProtocolValidationError) as error:
        authenticator.authenticate(request)

    assert error.value.code == "assertion_replay_detected"


def test_form_client_id_must_match_signed_issuer() -> None:
    """An attacker cannot pair another client_id with a valid signed assertion."""
    builder, authenticator, signing_key = build_flow()
    request = builder.build(
        client_id="parking-host",
        token_endpoint=TOKEN_ENDPOINT,
        signing_key=signing_key,
    ).model_copy(update={"client_id": "attacker-client"})

    with pytest.raises(ProtocolValidationError) as error:
        authenticator.authenticate(request)

    assert error.value.code == "client_identifier_mismatch"
