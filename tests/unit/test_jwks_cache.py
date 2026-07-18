"""Unit tests for bounded and expiring JWKS cache behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_nebula_sdk.jose.jwks.cache import JwksCache
from agent_nebula_sdk.jose.jwks.models import JwkSet


class MutableClock:
    """Minimal deterministic clock for cache expiration tests."""

    def __init__(self) -> None:
        self.current = datetime(2026, 7, 18, tzinfo=UTC)

    def now(self) -> datetime:
        """Return the mutable deterministic time used by cache tests."""
        return self.current


def test_rejects_invalid_configuration() -> None:
    """Cache capacity and entry TTL must be positive."""
    clock = MutableClock()
    with pytest.raises(ValueError):
        JwksCache(clock=clock, maximum_entries=0)


def test_expired_entry_is_removed(rsa_public_jwk: dict[str, str]) -> None:
    """Expired JWK Sets are not returned to key validators."""
    clock = MutableClock()
    cache = JwksCache(clock=clock)
    jwks = JwkSet.from_untrusted_mapping({"keys": [rsa_public_jwk]})
    cache.put("https://one.example/jwks", jwks, ttl=timedelta(seconds=1))

    clock.current += timedelta(seconds=2)

    assert cache.get("https://one.example/jwks") is None


def test_evicts_earliest_expiring_entry(
    rsa_public_jwk: dict[str, str],
    ec_public_jwk: dict[str, str],
) -> None:
    """A bounded cache evicts the entry with the earliest expiration."""
    clock = MutableClock()
    cache = JwksCache(clock=clock, maximum_entries=1)
    first = JwkSet.from_untrusted_mapping({"keys": [rsa_public_jwk]})
    second = JwkSet.from_untrusted_mapping({"keys": [ec_public_jwk]})
    cache.put("https://one.example/jwks", first, ttl=timedelta(minutes=1))
    cache.put("https://two.example/jwks", second, ttl=timedelta(minutes=2))

    assert cache.get("https://one.example/jwks") is None
    assert cache.get("https://two.example/jwks") == second


def test_rejects_non_positive_ttl(rsa_public_jwk: dict[str, str]) -> None:
    """Entries cannot be stored without a meaningful expiration."""
    cache = JwksCache(clock=MutableClock())
    jwks = JwkSet.from_untrusted_mapping({"keys": [rsa_public_jwk]})

    with pytest.raises(ValueError):
        cache.put("https://one.example/jwks", jwks, ttl=timedelta(0))
