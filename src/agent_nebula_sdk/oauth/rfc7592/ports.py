"""Persistence, credential, and lifecycle ports for RFC 7592.

The SDK owns protocol rules only. Authorization Server products provide storage,
credential hashing, credential generation, endpoint construction, and optional
token/grant revocation adapters.
"""

from __future__ import annotations

from typing import Protocol

from agent_nebula_sdk.oauth.rfc7591.models import RegisteredClientRecord
from agent_nebula_sdk.oauth.rfc7592.models import ClientConfigurationRecord


class ClientConfigurationRepository(Protocol):
    """Persist RFC 7592 management state without defining a database schema."""

    def find(self, client_id: str) -> ClientConfigurationRecord | None:
        """Return active management state for a client, if it exists."""
        ...

    def save(self, record: ClientConfigurationRecord) -> None:
        """Persist newly provisioned RFC 7592 management state atomically."""
        ...

    def replace_client(self, record: ClientConfigurationRecord) -> None:
        """Replace client registration metadata while preserving management state."""
        ...

    def delete(self, client_id: str) -> None:
        """Delete or deactivate the managed client registration."""
        ...


class RegistrationAccessTokenGenerator(Protocol):
    """Generate high-entropy RFC 7592 registration access tokens."""

    def generate(self) -> str:
        """Return a new opaque registration access token."""
        ...


class RegistrationAccessTokenCodec(Protocol):
    """Hash and verify registration access tokens without storing plaintext."""

    def encode(self, token: str) -> str:
        """Return the durable non-reversible representation of a token."""
        ...

    def matches(self, token: str, encoded_token: str) -> bool:
        """Return whether a presented token matches durable state."""
        ...


class ClientConfigurationUriFactory(Protocol):
    """Create the server-owned RFC 7592 client configuration URI."""

    def create(self, client_id: str) -> str:
        """Return the absolute configuration URI for the registered client."""
        ...


class ClientRegistrationLifecycle(Protocol):
    """Apply product-owned cleanup after RFC 7592 deprovisioning."""

    def revoke_associated_artifacts(self, client_id: str) -> None:
        """Revoke associated grants and tokens where the product can do so."""
        ...


class ClientRegistrationUpdatePolicy(Protocol):
    """Authorize and validate RFC 7592 client metadata replacement."""

    def validate(self, current: RegisteredClientRecord, updated: RegisteredClientRecord) -> None:
        """Raise when the requested full replacement is not permitted."""
        ...
