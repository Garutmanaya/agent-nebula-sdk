"""Authorization Server service implementing RFC 7592 registration management."""

from __future__ import annotations

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7591.models import RegisteredClientRecord
from agent_nebula_sdk.oauth.rfc7592.models import (
    ClientConfigurationCredentials,
    ClientConfigurationRecord,
    ClientConfigurationResponse,
    ClientUpdateRequest,
)
from agent_nebula_sdk.oauth.rfc7592.ports import (
    ClientConfigurationRepository,
    ClientConfigurationUriFactory,
    ClientRegistrationLifecycle,
    ClientRegistrationUpdatePolicy,
    RegistrationAccessTokenCodec,
    RegistrationAccessTokenGenerator,
)


class ClientRegistrationManagementService:
    """Read, replace, and delete RFC 7592 client registrations.

    The service never owns HTTP routing or persistence. A standalone
    Authorization Server composes these protocol rules with product adapters.
    """

    def __init__(
        self,
        *,
        repository: ClientConfigurationRepository,
        token_generator: RegistrationAccessTokenGenerator,
        token_codec: RegistrationAccessTokenCodec,
        uri_factory: ClientConfigurationUriFactory,
        update_policy: ClientRegistrationUpdatePolicy | None = None,
        lifecycle: ClientRegistrationLifecycle | None = None,
    ) -> None:
        """Configure management persistence, credentials, policy, and lifecycle hooks."""
        self._repository = repository
        self._token_generator = token_generator
        self._token_codec = token_codec
        self._uri_factory = uri_factory
        self._update_policy = update_policy
        self._lifecycle = lifecycle

    def provision(self, client: RegisteredClientRecord) -> ClientConfigurationResponse:
        """Issue RFC 7592 management credentials for an RFC 7591 registration."""
        credentials = self._new_credentials(client.client_id)
        self._repository.save(
            ClientConfigurationRecord(
                client=client,
                registration_client_uri=credentials.registration_client_uri,
                registration_access_token_hash=self._token_codec.encode(
                    credentials.registration_access_token
                ),
            )
        )
        return ClientConfigurationResponse.from_record(client, credentials=credentials)

    def read(
        self,
        *,
        client_id: str,
        registration_access_token: str,
    ) -> ClientConfigurationResponse:
        """Read current client configuration after RFC 7592 Bearer authentication."""
        record = self._authenticate(client_id, registration_access_token)
        return self._respond_with_rotated_token(record)

    def update(
        self,
        *,
        request: ClientUpdateRequest,
        registration_access_token: str,
    ) -> ClientConfigurationResponse:
        """Replace registered metadata while keeping the RFC 7592 client ID immutable."""
        current = self._authenticate(request.client_id, registration_access_token)
        if (
            request.client_secret is not None
            and request.client_secret != current.client.client_secret
        ):
            raise ProtocolValidationError(
                "client_secret does not match the currently issued secret",
                code="invalid_client_metadata",
            )

        updated = RegisteredClientRecord(
            client_id=current.client.client_id,
            client_id_issued_at=current.client.client_id_issued_at,
            client_secret=current.client.client_secret,
            client_secret_expires_at=current.client.client_secret_expires_at,
            metadata=request.metadata.standard_metadata(),
            registration_method=current.client.registration_method,
            trust_status=current.client.trust_status,
            is_active=current.client.is_active,
        )
        if self._update_policy is not None:
            self._update_policy.validate(current.client, updated)

        replacement = current.model_copy(update={"client": updated})
        self._repository.replace_client(replacement)
        return self._respond_with_rotated_token(replacement)

    def delete(self, *, client_id: str, registration_access_token: str) -> None:
        """Deprovision a client and invalidate its RFC 7592 management credential."""
        self._authenticate(client_id, registration_access_token)
        self._repository.delete(client_id)
        if self._lifecycle is not None:
            self._lifecycle.revoke_associated_artifacts(client_id)

    def _authenticate(
        self,
        client_id: str,
        registration_access_token: str,
    ) -> ClientConfigurationRecord:
        """Authenticate a management request using its client-bound Bearer token."""
        record = self._repository.find(client_id)
        if record is None or not self._token_codec.matches(
            registration_access_token,
            record.registration_access_token_hash,
        ):
            raise ProtocolValidationError(
                "invalid registration access token or client registration",
                code="invalid_registration_access_token",
            )
        return record

    def _respond_with_rotated_token(
        self,
        record: ClientConfigurationRecord,
    ) -> ClientConfigurationResponse:
        """Rotate the management Bearer token and return current client information."""
        # RFC 7592 permits token rotation on read/update. The SDK reference service
        # always rotates so durable adapters can store only a non-reversible token hash.
        token = self._token_generator.generate()
        credentials = ClientConfigurationCredentials(
            client_id=record.client.client_id,
            registration_client_uri=record.registration_client_uri,
            registration_access_token=token,
        )
        replacement = record.model_copy(
            update={"registration_access_token_hash": self._token_codec.encode(token)}
        )
        self._repository.replace_client(replacement)
        return ClientConfigurationResponse.from_record(record.client, credentials=credentials)

    def _new_credentials(self, client_id: str) -> ClientConfigurationCredentials:
        """Create server-issued RFC 7592 configuration URI and management token."""
        return ClientConfigurationCredentials(
            client_id=client_id,
            registration_client_uri=self._uri_factory.create(client_id),
            registration_access_token=self._token_generator.generate(),
        )
