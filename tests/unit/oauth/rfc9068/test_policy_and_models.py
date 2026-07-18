"""Policy and model tests for RFC 9068 access tokens."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent_nebula_sdk.oauth.rfc9068.models import AccessTokenClaims
from agent_nebula_sdk.oauth.rfc9068.policy import Rfc9068Policy


def test_policy_requires_rs256() -> None:
    """RFC 9068 conforming implementations must include RS256 support."""
    with pytest.raises(ValidationError):
        Rfc9068Policy(allowed_algorithms=frozenset({"ES256"}))


def test_policy_rejects_none_algorithm() -> None:
    """Unsigned JWT access tokens are prohibited by RFC 9068 Section 2.1."""
    with pytest.raises(ValidationError):
        Rfc9068Policy(allowed_algorithms=frozenset({"RS256", "none"}))


def test_claims_normalize_single_audience() -> None:
    """A string audience is exposed as a one-element validation tuple."""
    claims = AccessTokenClaims(
        iss="https://issuer.example",
        sub="client-a",
        aud="https://provider.example",
        exp=200,
        iat=100,
        jti="token-1",
        client_id="client-a",
    )
    assert claims.audiences() == ("https://provider.example",)


def test_claims_reject_expiration_before_issue_time() -> None:
    """Expiration must be strictly later than token issuance."""
    with pytest.raises(ValidationError):
        AccessTokenClaims(
            iss="https://issuer.example",
            sub="client-a",
            aud="https://provider.example",
            exp=100,
            iat=100,
            jti="token-1",
            client_id="client-a",
        )


def test_policy_rejects_non_positive_lifetime() -> None:
    """Issuers cannot be configured to create already-expired tokens."""
    with pytest.raises(ValidationError):
        Rfc9068Policy(token_lifetime=timedelta(0))
