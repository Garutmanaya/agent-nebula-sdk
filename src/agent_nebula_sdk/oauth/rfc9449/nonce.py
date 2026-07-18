"""Server nonce issuance helper for RFC 9449 Section 8 challenges."""

from __future__ import annotations

from datetime import timedelta

from agent_nebula_sdk.oauth.rfc9449.ports import DpopNonceStore
from agent_nebula_sdk.ports.clock import Clock


class DpopNonceService:
    """Issue short-lived, single-use nonces through a product-owned store."""

    def __init__(
        self,
        *,
        clock: Clock,
        store: DpopNonceStore,
        lifetime: timedelta = timedelta(minutes=5),
    ) -> None:
        """Inject deterministic time, persistence, and nonce lifetime."""
        if lifetime <= timedelta(0):
            raise ValueError("nonce lifetime must be positive")
        self._clock = clock
        self._store = store
        self._lifetime = lifetime

    def issue(self, *, context: str) -> str:
        """Issue one nonce scoped to a token or protected-resource context."""
        if not context.strip():
            raise ValueError("nonce context must not be empty")
        return self._store.issue(
            context=context,
            expires_at=self._clock.now() + self._lifetime,
        )
