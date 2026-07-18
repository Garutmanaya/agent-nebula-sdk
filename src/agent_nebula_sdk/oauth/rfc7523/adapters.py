"""Reference in-memory adapters for RFC 7523 tests and local development.

These adapters are intentionally simple and thread-safe. Production Agent
Nebula deployments should implement the same ports with durable PostgreSQL or
Redis storage as appropriate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any

from agent_nebula_sdk.core.errors import KeyResolutionError
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk
from agent_nebula_sdk.ports.clock import Clock, SystemClock


@dataclass(frozen=True, slots=True)
class InMemoryRegisteredClient:
    """Immutable registered-client record used by reference adapters."""

    client_id: str
    is_active: bool = True
    token_endpoint_auth_method: str = "private_key_jwt"
    metadata: dict[str, Any] = field(default_factory=dict)


class InMemoryRegisteredClientStore:
    """Store registered clients in process memory for tests and examples."""

    def __init__(self, clients: tuple[InMemoryRegisteredClient, ...] = ()) -> None:
        """Initialize the store from immutable client records."""
        self._clients = {client.client_id: client for client in clients}

    def get_client(self, client_id: str) -> InMemoryRegisteredClient | None:
        """Return one client without exposing mutable internal state."""
        return self._clients.get(client_id)

    def put(self, client: InMemoryRegisteredClient) -> None:
        """Insert or replace a client record for local development."""
        self._clients[client.client_id] = client


class InMemoryClientKeyResolver:
    """Resolve registered client keys from an in-memory mapping."""

    def __init__(self) -> None:
        """Create an empty client-key mapping."""
        self._keys: dict[tuple[str, str], SupportedPublicJwk] = {}

    def put(self, *, client_id: str, key: SupportedPublicJwk) -> None:
        """Register a public JWK for one client and key identifier."""
        if key.kid is None:
            raise ValueError("registered client key requires kid")
        self._keys[(client_id, key.kid)] = key

    def resolve_client_key(
        self,
        *,
        client_id: str,
        key_id: str,
        algorithm: str,
    ) -> SupportedPublicJwk:
        """Resolve a key and enforce its declared algorithm when present."""
        key = self._keys.get((client_id, key_id))
        if key is None or (key.alg is not None and key.alg != algorithm):
            raise KeyResolutionError(
                "registered client key could not be resolved",
                code="client_key_not_found",
                details={"client_id": client_id, "kid": key_id},
            )
        return key


class InMemoryAuthorizationGrantKeyResolver:
    """Resolve authorization-grant issuer keys from process memory."""

    def __init__(self) -> None:
        """Create an empty issuer-key mapping."""
        self._keys: dict[tuple[str, str], SupportedPublicJwk] = {}

    def put(self, *, issuer: str, key: SupportedPublicJwk) -> None:
        """Register a public JWK for one assertion issuer."""
        if key.kid is None:
            raise ValueError("authorization-grant key requires kid")
        self._keys[(issuer, key.kid)] = key

    def resolve_issuer_key(
        self,
        *,
        issuer: str,
        key_id: str,
        algorithm: str,
    ) -> SupportedPublicJwk:
        """Resolve an issuer key and enforce its algorithm declaration."""
        key = self._keys.get((issuer, key_id))
        if key is None or (key.alg is not None and key.alg != algorithm):
            raise KeyResolutionError(
                "authorization-grant issuer key could not be resolved",
                code="issuer_key_not_found",
                details={"issuer": issuer, "kid": key_id},
            )
        return key


class InMemoryAssertionReplayStore:
    """Atomically reject repeated assertion identifiers within one process."""

    def __init__(self, *, clock: Clock | None = None) -> None:
        """Create an empty replay store protected by a process-local lock."""
        self._entries: dict[tuple[str, str, str], datetime] = {}
        self._lock = Lock()
        self._clock = clock or SystemClock()

    def consume(
        self,
        *,
        namespace: str,
        subject: str,
        assertion_id: str,
        expires_at: datetime,
    ) -> bool:
        """Record an assertion exactly once and return whether it was accepted."""
        key = (namespace, subject, assertion_id)
        with self._lock:
            self._remove_expired(now=self._clock.now())
            if key in self._entries:
                return False
            self._entries[key] = expires_at
            return True

    def _remove_expired(self, *, now: datetime) -> None:
        """Remove expired identifiers before evaluating a new assertion."""
        expired = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired:
            del self._entries[key]
