"""Thread-safe in-memory RFC 9449 adapters for tests and local development.

Production distributed deployments should use an atomic shared store such as
Redis or PostgreSQL. These adapters deliberately expose the same persistence
ports without making storage part of the SDK core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from secrets import token_urlsafe
from threading import Lock

from agent_nebula_sdk.ports.clock import Clock, SystemClock


@dataclass(slots=True)
class InMemoryDpopReplayStore:
    """Reject repeated proof identifiers using an atomic in-process map."""

    clock: Clock = field(default_factory=SystemClock)
    _entries: dict[tuple[str, str], datetime] = field(default_factory=dict, init=False)
    _lock: Lock = field(default_factory=Lock, init=False)

    def consume(
        self,
        *,
        proof_id: str,
        key_thumbprint: str,
        expires_at: datetime,
    ) -> bool:
        """Atomically store a new proof or report that it was already consumed."""
        identity = (key_thumbprint, proof_id)
        now = self.clock.now()
        with self._lock:
            self._entries = {key: expiry for key, expiry in self._entries.items() if expiry > now}
            if identity in self._entries:
                return False
            self._entries[identity] = expires_at
            return True


@dataclass(slots=True)
class InMemoryDpopNonceStore:
    """Issue and consume single-use nonces for deterministic local profiles."""

    clock: Clock = field(default_factory=SystemClock)
    _entries: dict[tuple[str, str], datetime] = field(default_factory=dict, init=False)
    _lock: Lock = field(default_factory=Lock, init=False)

    def issue(self, *, context: str, expires_at: datetime) -> str:
        """Generate a collision-resistant nonce and persist its expiry."""
        nonce = token_urlsafe(32)
        with self._lock:
            self._entries[(context, nonce)] = expires_at
        return nonce

    def consume(self, *, context: str, nonce: str) -> bool:
        """Atomically consume one live nonce and reject reuse or expiration."""
        identity = (context, nonce)
        now = self.clock.now()
        with self._lock:
            expires_at = self._entries.pop(identity, None)
            return expires_at is not None and expires_at > now
