"""Unit tests for RFC 7591 registration service behavior."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7591.adapters import InMemoryRegisteredClientRepository
from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata, RegistrationRequest
from agent_nebula_sdk.oauth.rfc7591.policy import (
    InitialAccessTokenRegistrationPolicy,
    OpenRegistrationPolicy,
)
from agent_nebula_sdk.oauth.rfc7591.service import DynamicClientRegistrationService


class FixedClock:
    """Return a deterministic instant for issued-at assertions."""

    def now(self) -> datetime:
        """Return the fixed UTC instant used by the test."""
        return datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


class SequentialIdentifierGenerator:
    """Return identifiers from a deterministic sequence."""

    def __init__(self, values: list[str]) -> None:
        """Store identifiers returned in order."""
        self._values = iter(values)

    def generate(self) -> str:
        """Return the next configured identifier."""
        return next(self._values)


def machine_metadata(rsa_public_jwk: dict[str, str]) -> ClientMetadata:
    """Build valid private-key JWT machine-client metadata."""
    return ClientMetadata.model_validate(
        {
            "client_name": "Parking Metro A",
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "jwks": {"keys": [rsa_public_jwk]},
            "software_id": "parking-metro-a",
            "software_version": "1.0.0",
        }
    )


def test_open_registration_assigns_unverified_trust(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Public registrations are accepted but classified as unverified."""
    repository = InMemoryRegisteredClientRepository()
    service = DynamicClientRegistrationService(
        repository=repository,
        identifier_generator=SequentialIdentifierGenerator(["client-1"]),
        policy=OpenRegistrationPolicy(),
        clock=FixedClock(),
    )
    response = service.register(RegistrationRequest(metadata=machine_metadata(rsa_public_jwk)))
    record = repository.get("client-1")
    assert response.client_id == "client-1"
    assert record is not None
    assert record.trust_status == "UNVERIFIED"
    assert record.registration_method == "open_rfc7591"


def test_controlled_registration_requires_initial_access_token(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Controlled onboarding rejects missing or invalid bootstrap authorization."""
    service = DynamicClientRegistrationService(
        repository=InMemoryRegisteredClientRepository(),
        identifier_generator=SequentialIdentifierGenerator(["client-1"]),
        policy=InitialAccessTokenRegistrationPolicy(
            token_validator=lambda token: token == "valid-token"
        ),
        clock=FixedClock(),
    )
    with pytest.raises(ProtocolValidationError) as error:
        service.register(RegistrationRequest(metadata=machine_metadata(rsa_public_jwk)))
    assert error.value.code == "invalid_initial_access_token"


def test_identifier_collision_uses_next_candidate(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Identifier generation retries bounded collisions before persistence."""
    repository = InMemoryRegisteredClientRepository()
    first_service = DynamicClientRegistrationService(
        repository=repository,
        identifier_generator=SequentialIdentifierGenerator(["duplicate"]),
        policy=OpenRegistrationPolicy(),
        clock=FixedClock(),
    )
    first_service.register(RegistrationRequest(metadata=machine_metadata(rsa_public_jwk)))
    second_service = DynamicClientRegistrationService(
        repository=repository,
        identifier_generator=SequentialIdentifierGenerator(["duplicate", "new-client"]),
        policy=OpenRegistrationPolicy(),
        clock=FixedClock(),
    )
    response = second_service.register(
        RegistrationRequest(metadata=machine_metadata(rsa_public_jwk))
    )
    assert response.client_id == "new-client"


def test_duplicate_software_identity_can_be_rejected(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Enterprise profiles may enforce unique software registrations."""
    repository = InMemoryRegisteredClientRepository()
    service = DynamicClientRegistrationService(
        repository=repository,
        identifier_generator=SequentialIdentifierGenerator(["client-1", "client-2"]),
        policy=OpenRegistrationPolicy(),
        clock=FixedClock(),
        reject_duplicate_software_identity=True,
    )
    request = RegistrationRequest(metadata=machine_metadata(rsa_public_jwk))
    service.register(request)
    with pytest.raises(ProtocolValidationError) as error:
        service.register(request)
    assert error.value.code == "duplicate_software_identity"


def test_controlled_registration_accepts_valid_token(
    rsa_public_jwk: dict[str, str],
) -> None:
    """A verified initial access token produces the controlled trust classification."""
    repository = InMemoryRegisteredClientRepository()
    service = DynamicClientRegistrationService(
        repository=repository,
        identifier_generator=SequentialIdentifierGenerator(["controlled-client"]),
        policy=InitialAccessTokenRegistrationPolicy(
            token_validator=lambda token: token == "valid-token",
            trust_status="ENTERPRISE_VERIFIED",
        ),
        clock=FixedClock(),
    )
    response = service.register(
        RegistrationRequest(
            metadata=machine_metadata(rsa_public_jwk),
            initial_access_token="valid-token",
        )
    )
    record = repository.get(response.client_id)
    assert record is not None
    assert record.registration_method == "controlled_rfc7591"
    assert record.trust_status == "ENTERPRISE_VERIFIED"


def test_extension_validator_is_invoked(rsa_public_jwk: dict[str, str]) -> None:
    """Product extension validation is delegated without modifying the RFC module."""
    observed: list[str | None] = []

    def validate_extension(metadata: ClientMetadata) -> None:
        """Record the metadata passed to the product extension hook."""
        observed.append(metadata.client_name)

    service = DynamicClientRegistrationService(
        repository=InMemoryRegisteredClientRepository(),
        identifier_generator=SequentialIdentifierGenerator(["client-1"]),
        policy=OpenRegistrationPolicy(
            extension_validator=validate_extension,
            allowed_extension_names=frozenset({"agent_nebula_entity_type"}),
        ),
        clock=FixedClock(),
    )
    service.register(RegistrationRequest(metadata=machine_metadata(rsa_public_jwk)))
    assert observed == ["Parking Metro A"]


def test_identifier_allocation_has_bounded_failure(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Repeated identifier collisions fail rather than loop indefinitely."""
    repository = InMemoryRegisteredClientRepository()
    seed_service = DynamicClientRegistrationService(
        repository=repository,
        identifier_generator=SequentialIdentifierGenerator(["duplicate"]),
        policy=OpenRegistrationPolicy(),
        clock=FixedClock(),
    )
    seed_service.register(RegistrationRequest(metadata=machine_metadata(rsa_public_jwk)))
    service = DynamicClientRegistrationService(
        repository=repository,
        identifier_generator=SequentialIdentifierGenerator(["duplicate", "duplicate"]),
        policy=OpenRegistrationPolicy(),
        clock=FixedClock(),
        maximum_identifier_attempts=2,
    )
    with pytest.raises(ProtocolValidationError) as error:
        service.register(RegistrationRequest(metadata=machine_metadata(rsa_public_jwk)))
    assert error.value.code == "client_id_allocation_failed"


def test_service_rejects_invalid_identifier_attempt_limit() -> None:
    """The registration service requires a positive collision retry limit."""
    with pytest.raises(ValueError, match="must be positive"):
        DynamicClientRegistrationService(
            repository=InMemoryRegisteredClientRepository(),
            identifier_generator=SequentialIdentifierGenerator(["client-1"]),
            policy=OpenRegistrationPolicy(),
            clock=FixedClock(),
            maximum_identifier_attempts=0,
        )
