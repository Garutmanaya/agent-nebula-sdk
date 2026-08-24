"""Typed models for RFC 7592 Dynamic Client Registration Management.

RFC 7592 extends RFC 7591 with a client configuration endpoint and a
registration access token used to read, replace, or delete a registration.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata, RegisteredClientRecord


class ClientConfigurationCredentials(BaseModel):
    """Represent RFC 7592 management credentials issued for one client."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    client_id: str = Field(min_length=1, max_length=255)
    registration_client_uri: str
    registration_access_token: str = Field(min_length=16)

    @model_validator(mode="after")
    def validate_configuration_uri(self) -> ClientConfigurationCredentials:
        """Require the server-issued client configuration URI to use HTTPS."""
        parsed = urlsplit(self.registration_client_uri)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("registration_client_uri must be an absolute HTTPS URL")
        if parsed.fragment:
            raise ValueError("registration_client_uri must not contain a fragment")
        return self


class ClientConfigurationRecord(BaseModel):
    """Represent persistent RFC 7592 registration-management state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    client: RegisteredClientRecord
    registration_client_uri: str
    registration_access_token_hash: str


class ClientConfigurationResponse(BaseModel):
    """Represent an RFC 7592 client information response."""

    model_config = ConfigDict(extra="allow", frozen=True)

    registration_client_uri: str
    registration_access_token: str
    client_id: str
    client_id_issued_at: int | None = None
    client_secret: str | None = None
    client_secret_expires_at: int | None = None

    @classmethod
    def from_record(
        cls,
        record: RegisteredClientRecord,
        *,
        credentials: ClientConfigurationCredentials,
    ) -> ClientConfigurationResponse:
        """Create a complete RFC 7592 response from registration state."""
        payload: dict[str, Any] = dict(record.metadata)
        payload.update(
            {
                "registration_client_uri": credentials.registration_client_uri,
                "registration_access_token": credentials.registration_access_token,
                "client_id": record.client_id,
                "client_id_issued_at": record.client_id_issued_at,
                "client_secret": record.client_secret,
                "client_secret_expires_at": record.client_secret_expires_at,
            }
        )
        return cls.model_validate(payload)


class ClientUpdateRequest(BaseModel):
    """Represent an RFC 7592 full-replacement client update request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    client_id: str = Field(min_length=1, max_length=255)
    metadata: ClientMetadata
    client_secret: str | None = None
