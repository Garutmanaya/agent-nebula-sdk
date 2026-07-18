"""Integration tests for RFC 8707 client-to-provider resource selection."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8707 import (
    ExactResourceCanonicalizer,
    InMemoryResourceRegistry,
    ResourceAudienceValidator,
    ResourceIndicatorPolicy,
    ResourceIndicatorRequest,
    ResourceIndicatorValidator,
    ResourceRegistration,
    ResourceResolutionService,
)


def service(*, allow_multiple: bool = False) -> ResourceResolutionService:
    """Build an authorization-server service with Metro and Airport resources."""
    registry = InMemoryResourceRegistry(
        (
            ResourceRegistration(
                resource="https://metro.example/a2a",
                audience="parking-metro-a",
                aliases=("https://metro.example/",),
                metadata={"provider": "metro"},
            ),
            ResourceRegistration(
                resource="https://airport.example/a2a",
                audience="parking-airport-x",
            ),
        )
    )
    policy = ResourceIndicatorPolicy(maximum_resources=None if allow_multiple else 1)
    return ResourceResolutionService(
        registry=registry,
        validator=ResourceIndicatorValidator(policy),
        canonicalizer=ExactResourceCanonicalizer(),
    )


def test_alias_resolves_to_canonical_provider_audience() -> None:
    """A registered alias selects the canonical Metro A audience."""
    resolved = service().resolve(ResourceIndicatorRequest(resources=("https://metro.example/",)))
    assert resolved[0].canonical_resource == "https://metro.example/a2a"
    assert resolved[0].audience == "parking-metro-a"


def test_unknown_provider_returns_invalid_target() -> None:
    """The authorization server rejects an unregistered resource."""
    with pytest.raises(ProtocolValidationError) as error:
        service().resolve(ResourceIndicatorRequest(resources=("https://unknown.example/a2a",)))
    assert error.value.code == "invalid_target"


def test_requested_resource_must_be_subset_of_prior_grant() -> None:
    """A refresh request cannot expand to a provider not in the original grant."""
    request = ResourceIndicatorRequest(resources=("https://airport.example/a2a",))
    with pytest.raises(ProtocolValidationError) as error:
        service().resolve(
            request,
            granted_resources=("https://metro.example/a2a",),
        )
    assert error.value.details["ungranted_resources"] == ["https://airport.example/a2a"]


def test_metro_token_audience_is_rejected_by_airport() -> None:
    """Audience selection prevents cross-provider token reuse."""
    audience = service().resolve_single_audience(
        ResourceIndicatorRequest(resources=("https://metro.example/a2a",))
    )
    ResourceAudienceValidator(expected_audience="parking-metro-a").validate(audience)
    with pytest.raises(ProtocolValidationError):
        ResourceAudienceValidator(expected_audience="parking-airport-x").validate(audience)


def test_generic_service_resolves_multiple_registered_resources() -> None:
    """The core implementation supports RFC 8707 multiple-resource requests."""
    resolved = service(allow_multiple=True).resolve(
        ResourceIndicatorRequest(
            resources=(
                "https://metro.example/a2a",
                "https://airport.example/a2a",
            )
        )
    )
    assert [item.audience for item in resolved] == [
        "parking-metro-a",
        "parking-airport-x",
    ]
