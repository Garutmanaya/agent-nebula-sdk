"""Unit tests for RFC 7523 client and authorization-grant builders."""

from __future__ import annotations

from datetime import timedelta

import jwt
import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError, UnsupportedAlgorithmError
from agent_nebula_sdk.oauth.rfc7523.builder import (
    ClientAssertionBuilder,
    JwtAuthorizationGrantBuilder,
)
from agent_nebula_sdk.oauth.rfc7523.keys import PrivateKeyJwtSigningKey
from agent_nebula_sdk.oauth.rfc7523.policy import Rfc7523Policy
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_rsa_key_pair


def test_builds_private_key_jwt_with_required_claims() -> None:
    """A client assertion contains the required identity, audience, time, and replay claims."""
    private_key, _public_jwk = build_rsa_key_pair()
    clock = FixedClock()
    builder = ClientAssertionBuilder(
        clock=clock,
        policy=Rfc7523Policy(),
        assertion_id_factory=lambda: "assertion-123",
    )
    signing_key = PrivateKeyJwtSigningKey(
        key_id="rsa-client-2026-01",
        algorithm="RS256",
        private_key=private_key,
    )

    request = builder.build(
        client_id="parking-host",
        token_endpoint="https://nebula.example/oauth/token",
        signing_key=signing_key,
    )
    header = jwt.get_unverified_header(request.client_assertion)
    claims = jwt.decode(request.client_assertion, options={"verify_signature": False})

    assert request.client_id == "parking-host"
    assert header == {"alg": "RS256", "kid": "rsa-client-2026-01", "typ": "JWT"}
    assert claims["iss"] == "parking-host"
    assert claims["sub"] == "parking-host"
    assert claims["aud"] == "https://nebula.example/oauth/token"
    assert claims["jti"] == "assertion-123"
    assert claims["exp"] - claims["iat"] == 300


def test_can_omit_redundant_client_id_form_parameter() -> None:
    """Deployments may identify the client solely from the signed assertion issuer."""
    private_key, _public_jwk = build_rsa_key_pair()
    builder = ClientAssertionBuilder(clock=FixedClock(), policy=Rfc7523Policy())

    request = builder.build(
        client_id="parking-host",
        token_endpoint="https://nebula.example/oauth/token",
        signing_key=PrivateKeyJwtSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=private_key,
        ),
        include_client_id_parameter=False,
    )

    assert request.client_id is None
    assert "client_id" not in request.to_form_fields()


def test_rejects_non_https_token_endpoint() -> None:
    """The default profile does not sign assertions for a downgraded token endpoint."""
    private_key, _public_jwk = build_rsa_key_pair()
    builder = ClientAssertionBuilder(clock=FixedClock(), policy=Rfc7523Policy())

    with pytest.raises(ProtocolValidationError) as error:
        builder.build(
            client_id="parking-host",
            token_endpoint="http://nebula.example/oauth/token",
            signing_key=PrivateKeyJwtSigningKey(
                key_id="rsa-client-2026-01",
                algorithm="RS256",
                private_key=private_key,
            ),
        )

    assert error.value.code == "invalid_token_endpoint_audience"


def test_rejects_algorithm_outside_policy() -> None:
    """The client cannot select a signing algorithm not configured by policy."""
    private_key, _public_jwk = build_rsa_key_pair()
    builder = ClientAssertionBuilder(
        clock=FixedClock(),
        policy=Rfc7523Policy(allowed_algorithms=frozenset({"ES256"})),
    )

    with pytest.raises(UnsupportedAlgorithmError):
        builder.build(
            client_id="parking-host",
            token_endpoint="https://nebula.example/oauth/token",
            signing_key=PrivateKeyJwtSigningKey(
                key_id="rsa-client-2026-01",
                algorithm="RS256",
                private_key=private_key,
            ),
        )


def test_builds_authorization_grant_with_additional_claims() -> None:
    """The authorization-grant builder preserves non-reserved application claims."""
    private_key, _public_jwk = build_rsa_key_pair()
    builder = JwtAuthorizationGrantBuilder(
        clock=FixedClock(),
        policy=Rfc7523Policy(assertion_lifetime=timedelta(minutes=2)),
        assertion_id_factory=lambda: "grant-123",
    )

    request = builder.build(
        issuer="https://issuer.example",
        subject="user-123",
        audience="https://nebula.example/oauth/token",
        signing_key=PrivateKeyJwtSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=private_key,
        ),
        scope="registry:discover",
        additional_claims={"tenant": "example"},
    )
    claims = jwt.decode(request.assertion, options={"verify_signature": False})

    assert request.scope == "registry:discover"
    assert claims["sub"] == "user-123"
    assert claims["tenant"] == "example"
    assert claims["jti"] == "grant-123"
    assert claims["exp"] - claims["iat"] == 120


def test_authorization_grant_rejects_reserved_claim_override() -> None:
    """Additional grant claims cannot replace security-critical registered claims."""
    private_key, _public_jwk = build_rsa_key_pair()
    builder = JwtAuthorizationGrantBuilder(clock=FixedClock(), policy=Rfc7523Policy())

    with pytest.raises(ProtocolValidationError) as error:
        builder.build(
            issuer="https://issuer.example",
            subject="user-123",
            audience="https://nebula.example/oauth/token",
            signing_key=PrivateKeyJwtSigningKey(
                key_id="rsa-client-2026-01",
                algorithm="RS256",
                private_key=private_key,
            ),
            additional_claims={"aud": "https://attacker.example"},
        )

    assert error.value.code == "reserved_claim_override"
