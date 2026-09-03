"""OpenID Connect JWT validation with explicit issuer, audience, and key resolution."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

import jwt

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk

from .models import AuthenticatedIdentity


class OidcVerificationKeyResolver(Protocol):
    """Resolve an OIDC issuer signing key, normally through discovered JWKS metadata."""

    def resolve(
        self,
        *,
        issuer: str,
        key_id: str,
        algorithm: str,
    ) -> SupportedPublicJwk:
        """Return the trusted verification key for the issuer and JOSE header."""
        ...


class OidcJwtAuthenticator:
    """Validate a signed OIDC JWT using a trusted issuer and audience."""

    def __init__(
        self,
        *,
        key_resolver: OidcVerificationKeyResolver,
        allowed_algorithms: Sequence[str],
    ) -> None:
        """Configure trusted key resolution and an explicit algorithm allowlist."""
        self._resolver = key_resolver
        self._algorithms = tuple(allowed_algorithms)
        if not self._algorithms or "none" in self._algorithms:
            raise ValueError(
                "OIDC allowed_algorithms must be non-empty and must not contain 'none'"
            )

    def authenticate(
        self,
        token: str,
        *,
        issuer: str,
        audiences: Sequence[str],
    ) -> AuthenticatedIdentity:
        """Validate signature, issuer, audience, time claims, and subject."""
        if not audiences:
            raise ValueError("OIDC audiences must not be empty")
        try:
            header: dict[str, Any] = jwt.get_unverified_header(token)
            kid = header.get("kid")
            algorithm = header.get("alg")
            if (
                not isinstance(kid, str)
                or not kid
                or not isinstance(algorithm, str)
                or algorithm not in self._algorithms
            ):
                raise ValueError("invalid JOSE routing metadata")
            key = self._resolver.resolve(
                issuer=issuer,
                key_id=kid,
                algorithm=algorithm,
            )
            claims = jwt.decode(
                token,
                key=key.to_public_key(),
                algorithms=[algorithm],
                issuer=issuer,
                audience=list(audiences),
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
        except Exception as exc:  # Normalize parser, crypto, and resolver failures.
            raise ProtocolValidationError(
                "OpenID Connect token validation failed",
                code="invalid_oidc_token",
            ) from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ProtocolValidationError(
                "OpenID Connect token subject is missing",
                code="invalid_oidc_token",
            )
        return AuthenticatedIdentity(
            subject=subject,
            attributes={"claims": dict(claims)},
        )
