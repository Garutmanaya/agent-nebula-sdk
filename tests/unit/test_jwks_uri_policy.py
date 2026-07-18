"""Unit tests for open-registration JWKS URI security policy."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import KeyValidationError
from agent_nebula_sdk.jose.jwks.uri_policy import JwksUriPolicy


def test_accepts_https_uri_resolving_to_public_address() -> None:
    """A normal HTTPS JWKS endpoint with a public address is accepted."""
    policy = JwksUriPolicy(
        dns_resolver=lambda _hostname: ["203.0.113.10"], allow_private_networks=True
    )

    assert policy.validate("https://client.example/.well-known/jwks.json") == (
        "https://client.example/.well-known/jwks.json"
    )


@pytest.mark.parametrize(
    "uri",
    [
        "http://client.example/jwks.json",
        "https://user:password@client.example/jwks.json",
        "https://client.example/jwks.json#fragment",
    ],
)
def test_rejects_unsafe_uri_forms(uri: str) -> None:
    """Transport downgrade, user-info, and fragments are rejected."""
    policy = JwksUriPolicy(dns_resolver=lambda _hostname: ["8.8.8.8"])

    with pytest.raises(KeyValidationError):
        policy.validate(uri)


def test_rejects_private_network_resolution() -> None:
    """Open registration cannot use JWKS fetching as an SSRF primitive."""
    policy = JwksUriPolicy(dns_resolver=lambda _hostname: ["127.0.0.1"])

    with pytest.raises(KeyValidationError) as error:
        policy.validate("https://client.example/jwks.json")

    assert error.value.code == "unsafe_jwks_uri"


def test_allows_explicit_loopback_http_profile() -> None:
    """Local development can opt into HTTP loopback without weakening defaults."""
    policy = JwksUriPolicy(
        allow_http_for_loopback=True,
        allow_private_networks=True,
        dns_resolver=lambda _hostname: ["127.0.0.1"],
    )

    assert policy.validate("http://localhost:9000/jwks.json") == ("http://localhost:9000/jwks.json")


def test_rejects_unresolved_hostname() -> None:
    """A JWKS URI whose hostname has no addresses cannot be fetched safely."""
    policy = JwksUriPolicy(dns_resolver=lambda _hostname: [])

    with pytest.raises(KeyValidationError):
        policy.validate("https://missing.example/jwks.json")
