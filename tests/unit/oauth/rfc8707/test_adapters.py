"""Unit tests for RFC 8707 reference resource-registry adapters."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.oauth.rfc8707 import (
    InMemoryResourceRegistry,
    ResourceRegistration,
)


def registration(*, active: bool = True) -> ResourceRegistration:
    """Create one provider resource with an alternate URI alias."""
    return ResourceRegistration(
        resource="https://metro.example/a2a",
        audience="parking-metro-a",
        aliases=("https://metro.example/",),
        active=active,
    )


def test_registry_resolves_primary_resource_and_alias() -> None:
    """Aliases map to the same canonical resource and audience."""
    registry = InMemoryResourceRegistry((registration(),))
    assert registry.find("https://metro.example/a2a") is not None
    assert registry.find("https://metro.example/") == registration()


def test_registry_hides_inactive_resource() -> None:
    """Inactive providers cannot receive newly issued access tokens."""
    registry = InMemoryResourceRegistry((registration(active=False),))
    assert registry.find("https://metro.example/a2a") is None


def test_registry_rejects_identifier_collision() -> None:
    """Two providers cannot own the same resource or alias."""
    registry = InMemoryResourceRegistry((registration(),))
    with pytest.raises(ValueError, match="already exists"):
        registry.register(
            ResourceRegistration(
                resource="https://airport.example/a2a",
                audience="parking-airport-x",
                aliases=("https://metro.example/",),
            )
        )


def test_registration_rejects_duplicate_internal_alias() -> None:
    """A registration cannot repeat its primary identifier as an alias."""
    registry = InMemoryResourceRegistry()
    with pytest.raises(ValueError, match="duplicate identifiers"):
        registry.register(
            ResourceRegistration(
                resource="https://metro.example/a2a",
                audience="parking-metro-a",
                aliases=("https://metro.example/a2a",),
            )
        )
