"""Persistence and policy ports for RFC 7591 registration.

The SDK owns standards processing but never owns a database. Products provide
adapters for durable client storage, identifier generation, software statement
verification, and registration authorization policy.
"""

from __future__ import annotations

from typing import Protocol

from agent_nebula_sdk.oauth.rfc7591.models import (
    ClientMetadata,
    RegisteredClientRecord,
    RegistrationRequest,
)


class ClientIdentifierGenerator(Protocol):
    """Generate collision-resistant OAuth client identifiers."""

    def generate(self) -> str:
        """Return a new client identifier suitable for durable storage."""
        ...


class RegisteredClientRepository(Protocol):
    """Persist and query dynamically registered OAuth clients."""

    def exists(self, client_id: str) -> bool:
        """Return whether a client identifier already exists."""
        ...

    def save(self, record: RegisteredClientRecord) -> None:
        """Persist one validated registration atomically."""
        ...

    def find_by_software_identity(
        self,
        software_id: str,
        software_version: str | None,
    ) -> RegisteredClientRecord | None:
        """Find a prior registration using optional software identity metadata."""
        ...


class RegistrationPolicy(Protocol):
    """Authorize registration and classify its resulting trust posture."""

    def authorize(self, request: RegistrationRequest) -> None:
        """Raise a registration error when the request is not permitted."""
        ...

    def registration_method(self, request: RegistrationRequest) -> str:
        """Return an auditable label for the onboarding method."""
        ...

    def trust_status(self, request: RegistrationRequest) -> str:
        """Return the initial trust classification for the registered client."""
        ...

    def validate_extensions(self, metadata: ClientMetadata) -> None:
        """Validate product-specific metadata extensions without changing RFC code."""
        ...

    def allowed_extension_names(self) -> frozenset[str]:
        """Return product extension metadata names understood by this policy."""
        ...


class SoftwareStatementVerifier(Protocol):
    """Verify and decode an RFC 7591 software statement JWT."""

    def verify(self, statement: str) -> dict[str, object]:
        """Return trusted metadata claims from a valid software statement."""
        ...
