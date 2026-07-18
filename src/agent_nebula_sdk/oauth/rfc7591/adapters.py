"""Reference adapters for RFC 7591 tests and local development.

Production deployments should replace these adapters with product-specific
persistence and identifier generation implementations.
"""

from __future__ import annotations

import secrets
from threading import RLock

from agent_nebula_sdk.oauth.rfc7591.models import RegisteredClientRecord


class UrlSafeClientIdentifierGenerator:
    """Generate high-entropy URL-safe OAuth client identifiers."""

    def __init__(self, *, entropy_bytes: int = 24) -> None:
        """Configure the number of random bytes used for each identifier."""
        if entropy_bytes < 16:
            raise ValueError("entropy_bytes must be at least 16")
        self._entropy_bytes = entropy_bytes

    def generate(self) -> str:
        """Return a cryptographically random URL-safe identifier."""
        return secrets.token_urlsafe(self._entropy_bytes)


class InMemoryRegisteredClientRepository:
    """Thread-safe in-memory repository for tests and single-process examples."""

    def __init__(self) -> None:
        """Create an empty repository protected by a reentrant lock."""
        self._records: dict[str, RegisteredClientRecord] = {}
        self._lock = RLock()

    def exists(self, client_id: str) -> bool:
        """Return whether a client identifier is present."""
        with self._lock:
            return client_id in self._records

    def save(self, record: RegisteredClientRecord) -> None:
        """Persist one record and reject duplicate identifiers atomically."""
        with self._lock:
            if record.client_id in self._records:
                raise ValueError("client_id already exists")
            self._records[record.client_id] = record

    def find_by_software_identity(
        self,
        software_id: str,
        software_version: str | None,
    ) -> RegisteredClientRecord | None:
        """Find the first record matching software identity metadata."""
        with self._lock:
            for record in self._records.values():
                if record.metadata.get("software_id") != software_id:
                    continue
                if record.metadata.get("software_version") == software_version:
                    return record
        return None

    def get(self, client_id: str) -> RegisteredClientRecord | None:
        """Return one record for tests and local integration examples."""
        with self._lock:
            return self._records.get(client_id)
