"""End-to-end SDK flow from RFC 8707 audience resolution to RFC 9068 validation."""

from __future__ import annotations

from agent_nebula_sdk.oauth.rfc8707.adapters import (
    ExactResourceCanonicalizer,
    InMemoryResourceRegistry,
)
from agent_nebula_sdk.oauth.rfc8707.models import ResourceIndicatorRequest, ResourceRegistration
from agent_nebula_sdk.oauth.rfc8707.policy import (
    ResourceIndicatorPolicy,
    ResourceIndicatorValidator,
)
from agent_nebula_sdk.oauth.rfc8707.service import ResourceResolutionService
from agent_nebula_sdk.oauth.rfc9068.adapters import InMemoryAccessTokenKeyResolver
from agent_nebula_sdk.oauth.rfc9068.issuer import JwtAccessTokenIssuer
from agent_nebula_sdk.oauth.rfc9068.models import AccessTokenIssueRequest, AccessTokenSigningKey
from agent_nebula_sdk.oauth.rfc9068.policy import Rfc9068Policy
from agent_nebula_sdk.oauth.rfc9068.validator import JwtAccessTokenValidator
from tests.unit.oauth.rfc7523.helpers import FixedClock, build_rsa_key_pair


def test_resource_resolution_to_access_token_validation() -> None:
    """A resolved provider audience survives issuance and independent validation."""
    registry = InMemoryResourceRegistry()
    registry.register(
        ResourceRegistration(
            resource="https://metro.example/a2a",
            audience="https://metro.example/a2a",
        )
    )
    resolution = ResourceResolutionService(
        registry=registry,
        validator=ResourceIndicatorValidator(policy=ResourceIndicatorPolicy()),
        canonicalizer=ExactResourceCanonicalizer(),
    )
    audience = resolution.resolve_single_audience(
        ResourceIndicatorRequest(resources=("https://metro.example/a2a",))
    )

    private_key, public_jwk = build_rsa_key_pair()
    policy = Rfc9068Policy()
    token = (
        JwtAccessTokenIssuer(clock=FixedClock(), policy=policy)
        .issue(
            request=AccessTokenIssueRequest(
                issuer="https://nebula.example",
                subject="parking-host",
                audience=audience,
                client_id="parking-host",
            ),
            signing_key=AccessTokenSigningKey(
                key_id="rsa-client-2026-01",
                algorithm="RS256",
                private_key=private_key,
            ),
        )
        .token
    )

    keys = InMemoryAccessTokenKeyResolver()
    keys.register(issuer="https://nebula.example", key=public_jwk)
    validated = JwtAccessTokenValidator(
        clock=FixedClock(),
        policy=policy,
        key_resolver=keys,
    ).validate(
        token,
        expected_issuer="https://nebula.example",
        expected_audiences=("https://metro.example/a2a",),
    )
    assert validated.claims.audiences() == ("https://metro.example/a2a",)
