"""Adversarial unit tests for RFC 7523 JWT assertion validation."""

from __future__ import annotations

from datetime import timedelta

import jwt
import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError, UnsupportedAlgorithmError
from agent_nebula_sdk.oauth.rfc7523.builder import ClientAssertionBuilder
from agent_nebula_sdk.oauth.rfc7523.keys import PrivateKeyJwtSigningKey
from agent_nebula_sdk.oauth.rfc7523.policy import Rfc7523Policy
from agent_nebula_sdk.oauth.rfc7523.validator import JwtAssertionValidator
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_rsa_key_pair

TOKEN_ENDPOINT = "https://nebula.example/oauth/token"


def build_assertion(
    *,
    clock: FixedClock,
    lifetime: timedelta = timedelta(minutes=5),
) -> tuple[str, object]:
    """Create one valid RSA assertion and return it with the matching public JWK."""
    private_key, public_jwk = build_rsa_key_pair()
    builder = ClientAssertionBuilder(
        clock=clock,
        policy=Rfc7523Policy(assertion_lifetime=lifetime, maximum_assertion_lifetime=lifetime),
        assertion_id_factory=lambda: "assertion-123",
    )
    request = builder.build(
        client_id="parking-host",
        token_endpoint=TOKEN_ENDPOINT,
        signing_key=PrivateKeyJwtSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=private_key,
        ),
    )
    return request.client_assertion, public_jwk


def test_verifies_signature_audience_and_claims() -> None:
    """A valid assertion produces a verified header and typed claim mapping."""
    clock = FixedClock()
    assertion, public_jwk = build_assertion(clock=clock)
    validator = JwtAssertionValidator(clock=clock, policy=Rfc7523Policy())

    verified = validator.verify_client_assertion(
        assertion=assertion,
        public_jwk=public_jwk,  # type: ignore[arg-type]
        accepted_audiences=(TOKEN_ENDPOINT,),
    )

    assert verified.key_id == "rsa-client-2026-01"
    assert verified.algorithm == "RS256"
    assert verified.claims["iss"] == "parking-host"


def test_rejects_wrong_audience() -> None:
    """Assertions cannot be replayed to a different authorization server endpoint."""
    clock = FixedClock()
    assertion, public_jwk = build_assertion(clock=clock)
    validator = JwtAssertionValidator(clock=clock, policy=Rfc7523Policy())

    with pytest.raises(ProtocolValidationError) as error:
        validator.verify_client_assertion(
            assertion=assertion,
            public_jwk=public_jwk,  # type: ignore[arg-type]
            accepted_audiences=("https://other.example/oauth/token",),
        )

    assert error.value.code == "invalid_assertion_audience"


def test_rejects_wrong_signing_key() -> None:
    """An assertion signed by an unregistered private key fails cryptographic verification."""
    clock = FixedClock()
    assertion, _public_jwk = build_assertion(clock=clock)
    _other_private, other_public_jwk = build_rsa_key_pair()
    validator = JwtAssertionValidator(clock=clock, policy=Rfc7523Policy())

    with pytest.raises(ProtocolValidationError) as error:
        validator.verify_client_assertion(
            assertion=assertion,
            public_jwk=other_public_jwk,
            accepted_audiences=(TOKEN_ENDPOINT,),
        )

    assert error.value.code == "invalid_assertion_signature"


def test_rejects_missing_key_identifier() -> None:
    """The Phase 1 profile requires kid so key rotation remains deterministic."""
    private_key, public_jwk = build_rsa_key_pair()
    clock = FixedClock()
    now = int(clock.now().timestamp())
    assertion = jwt.encode(
        {
            "iss": "parking-host",
            "sub": "parking-host",
            "aud": TOKEN_ENDPOINT,
            "iat": now,
            "exp": now + 60,
            "jti": "assertion-123",
        },
        private_key,
        algorithm="RS256",
        headers={"typ": "JWT"},
    )
    validator = JwtAssertionValidator(clock=clock, policy=Rfc7523Policy())

    with pytest.raises(ProtocolValidationError) as error:
        validator.verify_client_assertion(
            assertion=assertion,
            public_jwk=public_jwk,
            accepted_audiences=(TOKEN_ENDPOINT,),
        )

    assert error.value.code == "missing_assertion_key_id"


def test_rejects_algorithm_not_in_policy() -> None:
    """The JOSE header cannot expand the configured algorithm allowlist."""
    clock = FixedClock()
    assertion, public_jwk = build_assertion(clock=clock)
    validator = JwtAssertionValidator(
        clock=clock,
        policy=Rfc7523Policy(allowed_algorithms=frozenset({"ES256"})),
    )

    with pytest.raises(UnsupportedAlgorithmError):
        validator.verify_client_assertion(
            assertion=assertion,
            public_jwk=public_jwk,  # type: ignore[arg-type]
            accepted_audiences=(TOKEN_ENDPOINT,),
        )


def test_rejects_assertion_lifetime_exceeding_server_policy() -> None:
    """Reject assertions that exceed the authorization server lifetime policy."""
    clock = FixedClock()
    assertion, public_jwk = build_assertion(clock=clock, lifetime=timedelta(minutes=10))
    validator = JwtAssertionValidator(
        clock=clock,
        policy=Rfc7523Policy(maximum_assertion_lifetime=timedelta(minutes=5)),
    )

    with pytest.raises(ProtocolValidationError) as error:
        validator.verify_client_assertion(
            assertion=assertion,
            public_jwk=public_jwk,  # type: ignore[arg-type]
            accepted_audiences=(TOKEN_ENDPOINT,),
        )

    assert error.value.code == "assertion_lifetime_too_long"


def test_rejects_malformed_compact_jwt() -> None:
    """Malformed compact serialization is mapped to a stable SDK error."""
    validator = JwtAssertionValidator(clock=FixedClock(), policy=Rfc7523Policy())

    with pytest.raises(ProtocolValidationError) as error:
        validator.read_unverified_header("not-a-jwt")

    assert error.value.code == "malformed_assertion_header"


def test_rejects_oversized_assertion_before_parsing() -> None:
    """Oversized attacker input is rejected before JSON parsing and signature work."""
    validator = JwtAssertionValidator(
        clock=FixedClock(),
        policy=Rfc7523Policy(maximum_assertion_bytes=512),
    )

    with pytest.raises(ProtocolValidationError) as error:
        validator.read_unverified_header("x" * 513)

    assert error.value.code == "assertion_too_large"


def test_rejects_expired_assertion_using_injected_clock() -> None:
    """Expiration is evaluated against the SDK clock rather than process wall time."""
    clock = FixedClock()
    assertion, public_jwk = build_assertion(clock=clock)
    clock.current += timedelta(minutes=10)
    validator = JwtAssertionValidator(clock=clock, policy=Rfc7523Policy())

    with pytest.raises(ProtocolValidationError) as error:
        validator.verify_client_assertion(
            assertion=assertion,
            public_jwk=public_jwk,  # type: ignore[arg-type]
            accepted_audiences=(TOKEN_ENDPOINT,),
        )

    assert error.value.code == "expired_assertion"
