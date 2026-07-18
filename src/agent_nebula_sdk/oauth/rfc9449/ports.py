"""Infrastructure ports used by RFC 9449 replay and nonce processing.

The SDK owns protocol validation but not persistence. Agent Nebula and provider
agents implement these ports with PostgreSQL, Redis, or another atomic store.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class DpopReplayStore(Protocol):
    """Atomically consume one DPoP proof identifier until its expiry time."""

    def consume(
        self,
        *,
        proof_id: str,
        key_thumbprint: str,
        expires_at: datetime,
    ) -> bool:
        """Return ``True`` only when the proof was not previously consumed."""


class DpopNonceStore(Protocol):
    """Issue and consume server-provided DPoP nonces.

    RFC 9449 Section 8 permits authorization servers and resource servers to
    require a fresh nonce to reduce pre-generated proof abuse.
    """

    def issue(self, *, context: str, expires_at: datetime) -> str:
        """Create and persist one nonce associated with a validation context."""

    def consume(self, *, context: str, nonce: str) -> bool:
        """Return ``True`` only when the nonce exists, is live, and is unused."""
