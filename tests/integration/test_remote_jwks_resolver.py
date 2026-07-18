"""Integration tests for outbound JWKS retrieval, caching, and refresh."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from agent_nebula_sdk.core.errors import ExternalServiceError
from agent_nebula_sdk.jose.jwks.cache import JwksCache
from agent_nebula_sdk.jose.jwks.resolver import RemoteJwksResolver
from agent_nebula_sdk.jose.jwks.uri_policy import JwksUriPolicy
from agent_nebula_sdk.ports.clock import Clock
from agent_nebula_sdk.ports.http import HttpResponse, HttpTransport


class FixedClock(Clock):
    """Deterministic mutable clock for cache behavior tests."""

    def __init__(self) -> None:
        self.current = datetime(2026, 7, 18, tzinfo=UTC)

    def now(self) -> datetime:
        return self.current


class RecordingTransport(HttpTransport):
    """Scripted transport that records each outbound request."""

    def __init__(self, responses: list[HttpResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append((url, headers))
        return self.responses.pop(0)


def build_resolver(transport: HttpTransport, clock: Clock) -> RemoteJwksResolver:
    """Create a resolver with deterministic network and time dependencies."""
    return RemoteJwksResolver(
        transport=transport,
        cache=JwksCache(clock=clock),
        uri_policy=JwksUriPolicy(
            allow_private_networks=True,
            dns_resolver=lambda _hostname: ["203.0.113.10"],
        ),
        default_ttl=timedelta(minutes=5),
    )


def response_for(keys: list[dict[str, str]], *, status_code: int = 200) -> HttpResponse:
    """Build a transport-neutral JSON response for a JWK Set."""
    return HttpResponse(
        status_code=status_code,
        headers={"content-type": "application/jwk-set+json"},
        body=json.dumps({"keys": keys}).encode("utf-8"),
    )


def test_fetches_and_caches_jwks(rsa_public_jwk: dict[str, str]) -> None:
    """Repeated reads use the validated cache rather than repeat HTTP calls."""
    clock = FixedClock()
    transport = RecordingTransport([response_for([rsa_public_jwk])])
    resolver = build_resolver(transport, clock)

    first = resolver.get_jwks("https://client.example/jwks.json")
    second = resolver.get_jwks("https://client.example/jwks.json")

    assert first == second
    assert len(transport.calls) == 1


def test_unknown_kid_refreshes_once(
    rsa_public_jwk: dict[str, str],
    ec_public_jwk: dict[str, str],
) -> None:
    """Key rotation can be discovered through one bounded unknown-kid refresh."""
    clock = FixedClock()
    transport = RecordingTransport(
        [
            response_for([rsa_public_jwk]),
            response_for([rsa_public_jwk, ec_public_jwk]),
        ]
    )
    resolver = build_resolver(transport, clock)

    selected = resolver.resolve_key(
        "https://client.example/jwks.json",
        kid="ec-2026-01",
        alg="ES256",
    )

    assert selected.kty == "EC"
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    ("response", "expected_code"),
    [
        (HttpResponse(status_code=503, headers={}, body=b"unavailable"), "jwks_http_error"),
        (HttpResponse(status_code=200, headers={}, body=b"not-json"), "invalid_jwks_response"),
        (HttpResponse(status_code=200, headers={}, body=b"[]"), "invalid_jwks_response"),
    ],
)
def test_external_response_failures_are_normalized(
    response: HttpResponse,
    expected_code: str,
) -> None:
    """Each external response failure produces a stable SDK error."""
    resolver = build_resolver(RecordingTransport([response]), FixedClock())

    with pytest.raises(ExternalServiceError) as error:
        resolver.get_jwks("https://client.example/jwks.json")

    assert error.value.code == expected_code


def test_rejects_invalid_resolver_configuration() -> None:
    """Response size and TTL limits cannot disable basic safety bounds."""
    transport = RecordingTransport([])
    cache = JwksCache(clock=FixedClock())
    policy = JwksUriPolicy(
        allow_private_networks=True,
        dns_resolver=lambda _hostname: ["203.0.113.10"],
    )
    with pytest.raises(ValueError):
        RemoteJwksResolver(
            transport=transport,
            cache=cache,
            uri_policy=policy,
            default_ttl=timedelta(0),
        )
    with pytest.raises(ValueError):
        RemoteJwksResolver(
            transport=transport,
            cache=cache,
            uri_policy=policy,
            maximum_response_bytes=0,
        )


def test_rejects_oversized_response(rsa_public_jwk: dict[str, str]) -> None:
    """A bounded resolver rejects documents above the configured size."""
    resolver = RemoteJwksResolver(
        transport=RecordingTransport([response_for([rsa_public_jwk])]),
        cache=JwksCache(clock=FixedClock()),
        uri_policy=JwksUriPolicy(
            allow_private_networks=True,
            dns_resolver=lambda _hostname: ["203.0.113.10"],
        ),
        maximum_response_bytes=1,
    )

    with pytest.raises(ExternalServiceError) as error:
        resolver.get_jwks("https://client.example/jwks.json")

    assert error.value.code == "jwks_response_too_large"


def test_rejects_structurally_invalid_jwks() -> None:
    """Valid JSON that violates the JWK Set schema is rejected."""
    response = HttpResponse(
        status_code=200,
        headers={},
        body=json.dumps({"keys": []}).encode("utf-8"),
    )
    resolver = build_resolver(RecordingTransport([response]), FixedClock())

    with pytest.raises(ExternalServiceError) as error:
        resolver.get_jwks("https://client.example/jwks.json")

    assert error.value.code == "invalid_jwks_response"
