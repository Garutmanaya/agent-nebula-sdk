"""Unit tests for RFC 7523 policy and typed OAuth request models."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ConfigurationError
from agent_nebula_sdk.oauth.rfc7523.constants import (
    JWT_BEARER_ASSERTION_TYPE,
    JWT_BEARER_GRANT_TYPE,
)
from agent_nebula_sdk.oauth.rfc7523.models import (
    ClientAssertionClaims,
    ClientAuthenticationRequest,
    JwtAuthorizationGrantRequest,
)
from agent_nebula_sdk.oauth.rfc7523.policy import Rfc7523Policy


def test_default_policy_is_short_lived_and_asymmetric() -> None:
    """The default profile permits only asymmetric algorithms and five-minute assertions."""
    policy = Rfc7523Policy()

    assert "none" not in policy.allowed_algorithms
    assert policy.assertion_lifetime == timedelta(minutes=5)
    assert policy.require_iat
    assert policy.require_jti
    assert policy.require_kid


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed_algorithms": frozenset()},
        {"allowed_algorithms": frozenset({"none"})},
        {"assertion_lifetime": timedelta(0)},
        {"maximum_assertion_lifetime": timedelta(0)},
        {
            "assertion_lifetime": timedelta(minutes=6),
            "maximum_assertion_lifetime": timedelta(minutes=5),
        },
        {"clock_skew": timedelta(seconds=-1)},
    ],
)
def test_rejects_unsafe_policy_configuration(kwargs: dict[str, object]) -> None:
    """Unsafe algorithm, lifetime, and skew policies fail during configuration."""
    with pytest.raises(ConfigurationError):
        Rfc7523Policy(**kwargs)  # type: ignore[arg-type]


def test_client_claims_require_same_issuer_and_subject() -> None:
    """RFC 7523 client authentication uses one client identifier for iss and sub."""
    with pytest.raises(ValidationError):
        ClientAssertionClaims(
            iss="client-a",
            sub="client-b",
            aud="https://nebula.example/oauth/token",
            iat=1,
            exp=2,
            jti="assertion-1",
        )


def test_client_authentication_request_serializes_registered_parameters() -> None:
    """The request model emits RFC 7521 client assertion form fields."""
    request = ClientAuthenticationRequest(
        client_assertion="signed.jwt.value",
        client_id="parking-host",
    )

    assert request.to_form_fields() == {
        "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
        "client_assertion": "signed.jwt.value",
        "client_id": "parking-host",
    }


def test_authorization_grant_request_serializes_registered_parameters() -> None:
    """The grant model emits the RFC 7521 JWT bearer grant parameters."""
    request = JwtAuthorizationGrantRequest(
        assertion="signed.jwt.value",
        scope="registry:discover",
    )

    assert request.to_form_fields() == {
        "grant_type": JWT_BEARER_GRANT_TYPE,
        "assertion": "signed.jwt.value",
        "scope": "registry:discover",
    }


def test_rejects_unregistered_assertion_parameter_values() -> None:
    """Incorrect assertion and grant URNs are rejected before network use."""
    with pytest.raises(ValidationError):
        ClientAuthenticationRequest(
            client_assertion_type="invalid",
            client_assertion="signed.jwt.value",
        )
    with pytest.raises(ValidationError):
        JwtAuthorizationGrantRequest(
            grant_type="invalid",
            assertion="signed.jwt.value",
        )


def test_rejects_unreasonably_small_assertion_size_limit() -> None:
    """The size policy cannot be configured below a minimally useful JWT size."""
    with pytest.raises(ConfigurationError):
        Rfc7523Policy(maximum_assertion_bytes=128)
