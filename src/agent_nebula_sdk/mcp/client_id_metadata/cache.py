"""Bounded thread-safe cache for validated Client ID Metadata Documents."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock

from agent_nebula_sdk.mcp.client_id_metadata.models import ResolvedClientIdMetadata
from agent_nebula_sdk.ports.clock import Clock


@dataclass(frozen=True, slots=True)
class CachedClientIdMetadata:
    """Store one validated document and its absolute expiration time."""

    value: ResolvedClientIdMetadata
    expires_at: datetime


class ClientIdMetadataCache:
    """Cache only valid documents and never cache retrieval or validation errors."""

    def __init__(self, *, clock: Clock, maximum_entries: int = 256) -> None:
        """Create a bounded cache with deterministic time behavior."""
        if maximum_entries < 1:
            raise ValueError("maximum_entries must be positive")
        self._clock = clock
        self._maximum_entries = maximum_entries
        self._entries: dict[str, CachedClientIdMetadata] = {}
        self._lock = RLock()

    def get(self, client_id: str) -> ResolvedClientIdMetadata | None:
        """Return a non-expired document or ``None``."""
        now = self._clock.now()
        with self._lock:
            cached = self._entries.get(client_id)
            if cached is None:
                return None
            if cached.expires_at <= now:
                self._entries.pop(client_id, None)
                return None
            return cached.value

    def put(self, value: ResolvedClientIdMetadata, *, ttl: timedelta) -> None:
        """Cache a validated document for a positive bounded duration."""
        if ttl <= timedelta(0):
            raise ValueError("metadata cache TTL must be positive")
        with self._lock:
            if (
                value.source_url not in self._entries
                and len(self._entries) >= self._maximum_entries
            ):
                oldest = min(self._entries, key=lambda key: self._entries[key].expires_at)
                self._entries.pop(oldest)
            self._entries[value.source_url] = CachedClientIdMetadata(
                value=value,
                expires_at=self._clock.now() + ttl,
            )

    def invalidate(self, client_id: str) -> None:
        """Remove one cached client metadata document."""
        with self._lock:
            self._entries.pop(client_id, None)
