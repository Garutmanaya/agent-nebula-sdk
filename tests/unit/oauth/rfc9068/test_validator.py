"""Resource-server validation tests for RFC 9068."""

from __future__ import annotations

import jwt
import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9068.adapters import InMemoryAccessTokenKeyResolver
from agent_nebula_sdk.oauth.rfc9068.issuer import JwtAccessTokenIssuer
from agent_nebula_sdk.oauth.rfc9068.models import AccessTokenIssueRequest, AccessTokenSigningKey
from agent_nebula_sdk.oauth.rfc9068.policy import Rfc9068Policy
from agent_nebula_sdk.oauth.rfc9068.validator import JwtAccessTokenValidator
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_rsa_key_pair


def issue_and_validator() -> tuple[str, JwtAccessTokenValidator, object]:
    """Create one valid token, validator, and private key for mutation tests."""
    private_key, public_jwk = build_rsa_key_pair()
    policy = Rfc9068Policy()
    issuer = JwtAccessTokenIssuer(
        clock=FixedClock(),
        policy=policy,
        token_id_factory=lambda: "token-1",
    )
    token = issuer.issue(
        request=AccessTokenIssueRequest(
            issuer="https://nebula.example",
            subject="parking-host",
            audience="https://metro.example/a2a",
            client_id="parking-host",
        ),
        signing_key=AccessTokenSigningKey(
            key_id="rsa-client-2026-01",
            algorithm="RS256",
            private_key=private_key,
        ),
    ).token
    resolver = InMemoryAccessTokenKeyResolver()
    resolver.register(issuer="https://nebula.example", key=public_jwk)
    validator = JwtAccessTokenValidator(
        clock=FixedClock(),
        policy=policy,
        key_resolver=resolver,
    )
    return token, validator, private_key


def test_validate_valid_token() -> None:
    """A correctly signed token produces a trusted claims model."""
    token, validator, _ = issue_and_validator()
    validated = validator.validate(
        token,
        expected_issuer="https://nebula.example",
        expected_audiences=("https://metro.example/a2a",),
    )
    assert validated.claims.client_id == "parking-host"
    assert validated.token_type == "at+jwt"


def test_validate_rejects_wrong_audience() -> None:
    """A Metro token cannot be replayed against Airport X."""
    token, validator, _ = issue_and_validator()
    with pytest.raises(ProtocolValidationError) as captured:
        validator.validate(
            token,
            expected_issuer="https://nebula.example",
            expected_audiences=("https://airport.example/a2a",),
        )
    assert captured.value.code == "invalid_token"


def test_validate_rejects_wrong_type() -> None:
    """ID-token-like JWTs are rejected before cross-JWT confusion is possible."""
    token, validator, private_key = issue_and_validator()
    claims = jwt.decode(token, options={"verify_signature": False})
    wrong_type = jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "rsa-client-2026-01", "typ": "JWT"},
    )
    with pytest.raises(ProtocolValidationError) as captured:
        validator.validate(
            wrong_type,
            expected_issuer="https://nebula.example",
            expected_audiences=("https://metro.example/a2a",),
        )
    assert captured.value.code == "invalid_token"


def test_validate_rejects_wrong_issuer() -> None:
    """Issuer matching is exact and tied to the trusted key namespace."""
    token, validator, _ = issue_and_validator()
    with pytest.raises(ProtocolValidationError):
        validator.validate(
            token,
            expected_issuer="https://other.example",
            expected_audiences=("https://metro.example/a2a",),
        )
