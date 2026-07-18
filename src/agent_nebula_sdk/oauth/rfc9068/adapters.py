"""Reference in-memory adapters for RFC 9068 tests and local development."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_nebula_sdk.core.errors import KeyResolutionError
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk


@dataclass(slots=True)
class InMemoryAccessTokenKeyResolver:
    """Resolve authorization-server verification keys from an in-memory map.

    This adapter is intentionally persistence-neutral and is not a production
    key-distribution mechanism. Providers should normally use RFC 8414 metadata
    plus the shared remote JWKS resolver.
    """

    keys: dict[tuple[str, str], SupportedPublicJwk] = field(default_factory=dict)

    def register(self, *, issuer: str, key: SupportedPublicJwk) -> None:
        """Register one issuer key for deterministic tests and examples."""
        if key.kid is None:
            raise ValueError("registered access-token verification keys require kid")
        self.keys[(issuer, key.kid)] = key

    def resolve(self, *, issuer: str, key_id: str, algorithm: str) -> SupportedPublicJwk:
        """Return a matching key or raise a stable SDK key-resolution error."""
        key = self.keys.get((issuer, key_id))
        if key is None:
            raise KeyResolutionError(
                "access-token verification key was not found",
                code="access_token_key_not_found",
                details={"issuer": issuer, "kid": key_id},
            )
        if key.alg is not None and key.alg != algorithm:
            raise KeyResolutionError(
                "access-token algorithm does not match the registered key",
                code="access_token_key_algorithm_mismatch",
                details={"expected": key.alg, "actual": algorithm},
            )
        return key
