"""Unit tests for RFC 7591 reference adapters."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.oauth.rfc7591.adapters import (
    InMemoryRegisteredClientRepository,
    UrlSafeClientIdentifierGenerator,
)
from agent_nebula_sdk.oauth.rfc7591.models import RegisteredClientRecord


def record(client_id: str) -> RegisteredClientRecord:
    """Create a minimal registered-client fixture."""
    return RegisteredClientRecord(
        client_id=client_id,
        metadata={"software_id": "software", "software_version": "1"},
        registration_method="open_rfc7591",
        trust_status="UNVERIFIED",
    )


def test_identifier_generator_requires_minimum_entropy() -> None:
    """Generated identifiers retain a minimum security margin."""
    with pytest.raises(ValueError, match="at least 16"):
        UrlSafeClientIdentifierGenerator(entropy_bytes=8)


def test_identifier_generator_returns_distinct_values() -> None:
    """Reference generation returns non-empty high-entropy identifiers."""
    generator = UrlSafeClientIdentifierGenerator()
    assert generator.generate() != generator.generate()


def test_repository_rejects_duplicate_client_identifier() -> None:
    """Reference persistence enforces identifier uniqueness atomically."""
    repository = InMemoryRegisteredClientRepository()
    repository.save(record("client-1"))
    with pytest.raises(ValueError, match="already exists"):
        repository.save(record("client-1"))


def test_repository_finds_software_identity() -> None:
    """Software identity lookup supports optional duplicate-registration policy."""
    repository = InMemoryRegisteredClientRepository()
    repository.save(record("client-1"))
    assert repository.find_by_software_identity("software", "1") is not None
    assert repository.find_by_software_identity("missing", "1") is None
