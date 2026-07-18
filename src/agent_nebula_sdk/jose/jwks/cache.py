"""Thread-safe bounded cache for remote JWK Sets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock

from agent_nebula_sdk.jose.jwks.models import JwkSet
from agent_nebula_sdk.ports.clock import Clock


@dataclass(frozen=True, slots=True)
class CachedJwkSet:
    """One cached JWK Set and its absolute expiration instant.

    Class responsibility
    -----------------------
    Provides bounded, thread-safe caching without changing protocol semantics.

    Standards
    ---------
    * RFC 7517
    * RFC 7517

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    value: JwkSet
    expires_at: datetime


class JwksCache:
    """Small thread-safe cache keyed by canonical JWKS URI.

    Class responsibility
    -----------------------
    Provides bounded, thread-safe caching without changing protocol semantics.

    Standards
    ---------
    * RFC 7517
    * RFC 7517

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def __init__(self, *, clock: Clock, maximum_entries: int = 256) -> None:
        """Create a bounded cache with deterministic time and capacity.

        Function responsibility
        -----------------------
        Provides bounded, thread-safe caching without changing protocol semantics.

        Standards
        ---------
        * RFC 7517
        * RFC 7517

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        if maximum_entries < 1:
            raise ValueError("maximum_entries must be positive")
        self._clock = clock
        self._maximum_entries = maximum_entries
        self._entries: dict[str, CachedJwkSet] = {}
        self._lock = RLock()

    def get(self, uri: str) -> JwkSet | None:
        """Return a non-expired cached JWK Set or ``None``.

        Function responsibility
        -----------------------
        Provides bounded, thread-safe caching without changing protocol semantics.

        Standards
        ---------
        * RFC 7517
        * RFC 7517

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        now = self._clock.now()
        with self._lock:
            cached = self._entries.get(uri)
            if cached is None:
                return None
            if cached.expires_at <= now:
                self._entries.pop(uri, None)
                return None
            return cached.value

    def put(self, uri: str, value: JwkSet, *, ttl: timedelta) -> None:
        """Store a JWK Set with a positive TTL and bounded cache size.

        Function responsibility
        -----------------------
        Provides bounded, thread-safe caching without changing protocol semantics.

        Standards
        ---------
        * RFC 7517
        * RFC 7517

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        if ttl <= timedelta(0):
            raise ValueError("JWKS cache TTL must be positive")
        with self._lock:
            if uri not in self._entries and len(self._entries) >= self._maximum_entries:
                oldest_uri = min(
                    self._entries,
                    key=lambda current_uri: self._entries[current_uri].expires_at,
                )
                self._entries.pop(oldest_uri)
            self._entries[uri] = CachedJwkSet(
                value=value,
                expires_at=self._clock.now() + ttl,
            )

    def invalidate(self, uri: str) -> None:
        """Remove one URI so an unknown ``kid`` can trigger a bounded refresh.

        Function responsibility
        -----------------------
        Provides bounded, thread-safe caching without changing protocol semantics.

        Standards
        ---------
        * RFC 7517
        * RFC 7517

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        with self._lock:
            self._entries.pop(uri, None)
