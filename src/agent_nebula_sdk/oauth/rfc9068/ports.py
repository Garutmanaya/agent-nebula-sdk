"""Infrastructure ports required by RFC 9068 resource-server validation."""

from __future__ import annotations

from typing import Protocol

from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk


class AccessTokenVerificationKeyResolver(Protocol):
    """Resolve an authorization-server public key by issuer and ``kid``.

    Agent Nebula may implement this with its local signing-key store. Independent
    providers normally implement it with the existing remote JWKS resolver.
    """

    def resolve(self, *, issuer: str, key_id: str, algorithm: str) -> SupportedPublicJwk:
        """Return the trusted public JWK used to verify an access token."""
