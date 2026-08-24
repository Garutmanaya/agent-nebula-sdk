"""Unit tests for RFC 7592 registration-management service behavior."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7591 import ClientMetadata, RegisteredClientRecord
from agent_nebula_sdk.oauth.rfc7592 import (
    BaseUrlClientConfigurationUriFactory,
    ClientRegistrationManagementService,
    ClientUpdateRequest,
    InMemoryClientConfigurationRepository,
    Sha256RegistrationAccessTokenCodec,
    UrlSafeRegistrationAccessTokenGenerator,
)


def _registered_client() -> RegisteredClientRecord:
    """Create one persistence-neutral RFC 7591 client for management tests."""
    metadata = ClientMetadata(
        grant_types=("client_credentials",),
        response_types=(),
        token_endpoint_auth_method="none",
        client_name="Original Client",
    )
    return RegisteredClientRecord(
        client_id="client-123",
        client_id_issued_at=1_700_000_000,
        metadata=metadata.standard_metadata(),
        registration_method="RFC7591",
        trust_status="STANDARD",
    )


def _service(
    repository: InMemoryClientConfigurationRepository,
) -> ClientRegistrationManagementService:
    """Build the RFC 7592 service with replaceable reference adapters."""
    return ClientRegistrationManagementService(
        repository=repository,
        token_generator=UrlSafeRegistrationAccessTokenGenerator(),
        token_codec=Sha256RegistrationAccessTokenCodec(),
        uri_factory=BaseUrlClientConfigurationUriFactory(
            base_url="https://oauth.example.test/register"
        ),
    )


def test_provision_read_update_and_delete_registration() -> None:
    """Exercise the RFC 7592 lifecycle while preserving the client identifier."""
    repository = InMemoryClientConfigurationRepository()
    service = _service(repository)

    provisioned = service.provision(_registered_client())
    assert provisioned.client_id == "client-123"
    assert provisioned.registration_client_uri.endswith("/client-123")

    read = service.read(
        client_id=provisioned.client_id,
        registration_access_token=provisioned.registration_access_token,
    )
    assert read.client_id == provisioned.client_id
    assert read.registration_access_token != provisioned.registration_access_token

    updated = service.update(
        request=ClientUpdateRequest(
            client_id="client-123",
            metadata=ClientMetadata(
                grant_types=("client_credentials",),
                response_types=(),
                token_endpoint_auth_method="none",
                client_name="Updated Client",
            ),
        ),
        registration_access_token=read.registration_access_token,
    )
    assert updated.client_id == "client-123"
    assert updated.client_name == "Updated Client"

    service.delete(
        client_id="client-123",
        registration_access_token=updated.registration_access_token,
    )
    assert repository.find("client-123") is None


def test_rotated_registration_access_token_invalidates_previous_token() -> None:
    """Reject a management credential after a successful RFC 7592 rotation."""
    repository = InMemoryClientConfigurationRepository()
    service = _service(repository)
    provisioned = service.provision(_registered_client())

    service.read(
        client_id=provisioned.client_id,
        registration_access_token=provisioned.registration_access_token,
    )

    with pytest.raises(ProtocolValidationError) as exc_info:
        service.read(
            client_id=provisioned.client_id,
            registration_access_token=provisioned.registration_access_token,
        )
    assert exc_info.value.code == "invalid_registration_access_token"
