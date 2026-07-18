"""RFC 9449 nonce, token-binding, URI, and hash helper tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from tests.unit.oauth.rfc7523.helpers import FixedClock

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9449.adapters import InMemoryDpopNonceStore
from agent_nebula_sdk.oauth.rfc9449.binding import DpopTokenBindingService
from agent_nebula_sdk.oauth.rfc9449.hash import AccessTokenHashService
from agent_nebula_sdk.oauth.rfc9449.nonce import DpopNonceService
from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy
from agent_nebula_sdk.oauth.rfc9449.uri import DpopTargetUriNormalizer


def test_nonce_is_single_use() -> None:
    """Issued nonces can be consumed once before their expiry."""
    clock = FixedClock()
    store = InMemoryDpopNonceStore(clock=clock)
    nonce = DpopNonceService(clock=clock, store=store).issue(context="token-endpoint")
    assert store.consume(context="token-endpoint", nonce=nonce)
    assert not store.consume(context="token-endpoint", nonce=nonce)


def test_nonce_expiration() -> None:
    """Expired server nonces are rejected by the persistence adapter."""
    clock = FixedClock()
    store = InMemoryDpopNonceStore(clock=clock)
    nonce = DpopNonceService(
        clock=clock,
        store=store,
        lifetime=timedelta(seconds=1),
    ).issue(context="resource")
    clock.current += timedelta(seconds=2)
    assert not store.consume(context="resource", nonce=nonce)


def test_token_binding_round_trip() -> None:
    """The standard ``cnf.jkt`` claim round-trips through the binding service."""
    service = DpopTokenBindingService()
    claim = service.build_confirmation_claim("thumbprint")
    assert service.extract_key_thumbprint(claim) == "thumbprint"
    assert service.is_dpop_bound(claim)


def test_invalid_token_binding_is_rejected() -> None:
    """Malformed confirmation claims never produce a trusted thumbprint."""
    with pytest.raises(ProtocolValidationError):
        DpopTokenBindingService().extract_key_thumbprint({"cnf": {}})


def test_uri_normalization_ignores_query_and_default_port() -> None:
    """RFC 9449 target comparison excludes query and normalizes default HTTPS port."""
    normalizer = DpopTargetUriNormalizer(policy=Rfc9449Policy())
    assert normalizer.normalize("https://EXAMPLE.com:443/a2a?x=1") == "https://example.com/a2a"


def test_access_token_hash_is_deterministic() -> None:
    """The same ASCII access token always produces the same ``ath`` value."""
    service = AccessTokenHashService()
    assert service.compute("token") == service.compute("token")


def test_policy_rejects_unsafe_configuration() -> None:
    """Unsigned algorithms and invalid timing values fail during configuration."""
    with pytest.raises(ValueError):
        Rfc9449Policy(allowed_algorithms=frozenset({"none"}))
    with pytest.raises(ValueError):
        Rfc9449Policy(maximum_proof_age=timedelta(0))
    with pytest.raises(ValueError):
        Rfc9449Policy(clock_skew=timedelta(seconds=-1))


def test_uri_normalizer_rejects_unsafe_targets() -> None:
    """Relative, insecure, fragmented, and hostless targets are rejected."""
    normalizer = DpopTargetUriNormalizer(policy=Rfc9449Policy())
    for value in (
        "/a2a",
        "http://example.com/a2a",
        "https://example.com/a2a#fragment",
        "https:///a2a",
    ):
        with pytest.raises(ProtocolValidationError):
            normalizer.normalize(value)


def test_hash_and_nonce_validate_required_input() -> None:
    """Empty access tokens, nonce contexts, and invalid lifetimes are rejected."""
    with pytest.raises(ValueError):
        AccessTokenHashService().compute("")
    clock = FixedClock()
    store = InMemoryDpopNonceStore(clock=clock)
    with pytest.raises(ValueError):
        DpopNonceService(clock=clock, store=store, lifetime=timedelta(0))
    with pytest.raises(ValueError):
        DpopNonceService(clock=clock, store=store).issue(context="")
