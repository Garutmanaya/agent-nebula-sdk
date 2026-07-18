"""Reusable RFC 9449 builders and deterministic cryptographic fixtures."""

from __future__ import annotations

from tests.unit.oauth.rfc7523.helpers import FixedClock

from agent_nebula_sdk.oauth.rfc9449.adapters import InMemoryDpopReplayStore
from agent_nebula_sdk.oauth.rfc9449.builder import DpopProofBuilder
from agent_nebula_sdk.oauth.rfc9449.hash import AccessTokenHashService
from agent_nebula_sdk.oauth.rfc9449.policy import Rfc9449Policy
from agent_nebula_sdk.oauth.rfc9449.uri import DpopTargetUriNormalizer
from agent_nebula_sdk.oauth.rfc9449.validator import DpopProofValidator


def build_policy(**overrides: object) -> Rfc9449Policy:
    """Return the default policy with selected test overrides."""
    return Rfc9449Policy.model_validate({**Rfc9449Policy().model_dump(), **overrides})


def build_builder(
    *,
    clock: FixedClock | None = None,
    policy: Rfc9449Policy | None = None,
) -> DpopProofBuilder:
    """Create a deterministic proof builder for unit tests."""
    active_clock = clock or FixedClock()
    active_policy = policy or Rfc9449Policy()
    return DpopProofBuilder(
        clock=active_clock,
        policy=active_policy,
        uri_normalizer=DpopTargetUriNormalizer(policy=active_policy),
        proof_id_factory=lambda: "11111111-1111-4111-8111-111111111111",
    )


def build_validator(
    *,
    clock: FixedClock | None = None,
    policy: Rfc9449Policy | None = None,
    replay_store: InMemoryDpopReplayStore | None = None,
) -> DpopProofValidator:
    """Create a deterministic validator with an in-memory replay store."""
    active_clock = clock or FixedClock()
    active_policy = policy or Rfc9449Policy()
    return DpopProofValidator(
        clock=active_clock,
        policy=active_policy,
        replay_store=replay_store or InMemoryDpopReplayStore(clock=active_clock),
        uri_normalizer=DpopTargetUriNormalizer(policy=active_policy),
        token_hash_service=AccessTokenHashService(),
    )
