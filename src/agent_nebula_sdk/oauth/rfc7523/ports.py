"""Infrastructure ports required by the RFC 7523 protocol module.

The SDK owns protocol processing but no product database. Agent Nebula supplies
PostgreSQL or Redis adapters, while SDK tests can use deterministic in-memory
implementations of these ports.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk


class ClientSigningKey(Protocol):
    """Private signing-key abstraction used by assertion builders."""

    @property
    def key_id(self) -> str:
        """Return the JOSE ``kid`` placed in the assertion header."""
        ...

    @property
    def algorithm(self) -> str:
        """Return the configured asymmetric JWS algorithm name."""
        ...

    @property
    def private_key(self) -> object:
        """Return a private-key object accepted by the configured JOSE library."""
        ...


class RegisteredClient(Protocol):
    """Minimal registered-client record needed for client authentication."""

    @property
    def client_id(self) -> str:
        """Return the OAuth client identifier."""
        ...

    @property
    def is_active(self) -> bool:
        """Return whether authentication is currently permitted."""
        ...

    @property
    def token_endpoint_auth_method(self) -> str:
        """Return the registered OAuth token-endpoint authentication method."""
        ...

    @property
    def metadata(self) -> dict[str, Any]:
        """Return non-secret metadata propagated into authentication context."""
        ...


class RegisteredClientStore(Protocol):
    """Resolve registered clients without coupling the SDK to persistence."""

    def get_client(self, client_id: str) -> RegisteredClient | None:
        """Return a registered client or ``None`` when it does not exist."""
        ...


class ClientPublicKeyResolver(Protocol):
    """Resolve one registered public key for a client assertion."""

    def resolve_client_key(
        self,
        *,
        client_id: str,
        key_id: str,
        algorithm: str,
    ) -> SupportedPublicJwk:
        """Return the validated public JWK matching client, ``kid``, and algorithm."""
        ...


class AssertionReplayStore(Protocol):
    """Atomically consume assertion identifiers to prevent replay."""

    def consume(
        self,
        *,
        namespace: str,
        subject: str,
        assertion_id: str,
        expires_at: datetime,
    ) -> bool:
        """Return ``True`` only for the first valid use of an assertion identifier."""
        ...


class AuthorizationGrantKeyResolver(Protocol):
    """Resolve a public key for an RFC 7523 authorization-grant issuer."""

    def resolve_issuer_key(
        self,
        *,
        issuer: str,
        key_id: str,
        algorithm: str,
    ) -> SupportedPublicJwk:
        """Return the public JWK registered for an assertion issuer."""
        ...
