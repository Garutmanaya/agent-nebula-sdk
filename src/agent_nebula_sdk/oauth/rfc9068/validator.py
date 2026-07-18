"""Resource-server validation for RFC 9068 JWT access tokens.

Validation deliberately checks token type before accepting claims, resolves the
issuer key through a product-owned port, verifies the signature with an explicit
algorithm allowlist, and then validates issuer, audience, and temporal claims.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, NoReturn

import jwt
from pydantic import ValidationError

from agent_nebula_sdk.core.errors import (
    AgentNebulaSdkError,
    ProtocolValidationError,
    UnsupportedAlgorithmError,
)
from agent_nebula_sdk.oauth.rfc9068.constants import INVALID_TOKEN_ERROR
from agent_nebula_sdk.oauth.rfc9068.models import AccessTokenClaims, ValidatedAccessToken
from agent_nebula_sdk.oauth.rfc9068.policy import Rfc9068Policy
from agent_nebula_sdk.oauth.rfc9068.ports import AccessTokenVerificationKeyResolver
from agent_nebula_sdk.ports.clock import Clock


class JwtAccessTokenValidator:
    """Validate RFC 9068 tokens at a resource-server trust boundary.

    Standards
    ---------
    RFC 9068 Section 4 and RFC 8725 Sections 3.1, 3.9, 3.11, and 3.12.
    """

    def __init__(
        self,
        *,
        clock: Clock,
        policy: Rfc9068Policy,
        key_resolver: AccessTokenVerificationKeyResolver,
    ) -> None:
        """Inject deterministic time, algorithm policy, and trusted key resolution."""
        self._clock = clock
        self._policy = policy
        self._key_resolver = key_resolver

    def validate(
        self,
        token: str,
        *,
        expected_issuer: str,
        expected_audiences: Sequence[str],
    ) -> ValidatedAccessToken:
        """Verify and normalize one incoming RFC 9068 access token.

        Raises a stable ``invalid_token`` protocol error for any untrusted token
        failure, allowing HTTP adapters to produce RFC 6750 responses later.
        """
        self._validate_size(token)
        if not expected_audiences:
            raise ValueError("expected_audiences must not be empty")

        header = self._read_header(token)
        token_type = self._read_token_type(header)
        key_id = self._read_required_header_string(header, "kid")
        algorithm = self._read_required_header_string(header, "alg")
        if algorithm not in self._policy.allowed_algorithms:
            raise UnsupportedAlgorithmError(
                "access-token signing algorithm is not allowed",
                code=INVALID_TOKEN_ERROR,
                details={"algorithm": algorithm},
            )

        try:
            public_jwk = self._key_resolver.resolve(
                issuer=expected_issuer,
                key_id=key_id,
                algorithm=algorithm,
            )
        except AgentNebulaSdkError as exc:
            raise ProtocolValidationError(
                "JWT access token verification key could not be resolved",
                code=INVALID_TOKEN_ERROR,
            ) from exc
        if public_jwk.use not in (None, "sig"):
            self._invalid("access-token key is not authorized for signatures")
        if public_jwk.key_ops not in (None, (), ("verify",)):
            self._invalid("access-token key is not authorized for verification")

        try:
            decoded = jwt.decode(
                token,
                key=public_jwk.to_public_key(),
                algorithms=[algorithm],
                issuer=expected_issuer,
                audience=list(expected_audiences),
                leeway=self._policy.clock_skew.total_seconds(),
                options={
                    "require": ["iss", "sub", "aud", "exp", "iat", "jti", "client_id"],
                    "verify_signature": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    # PyJWT validates against wall-clock time. The SDK disables
                    # those two checks here and applies the injected Clock below so
                    # tests and distributed deployments share deterministic semantics.
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
            claims = AccessTokenClaims.model_validate(decoded)
        except (
            jwt.PyJWTError,
            ValidationError,
            TypeError,
            ValueError,
        ) as exc:
            raise ProtocolValidationError(
                "JWT access token validation failed",
                code=INVALID_TOKEN_ERROR,
            ) from exc

        now_timestamp = int(self._clock.now().timestamp())
        skew_seconds = int(self._policy.clock_skew.total_seconds())
        if claims.iat > now_timestamp + skew_seconds:
            self._invalid("access token was issued in the future")
        if claims.exp <= now_timestamp - skew_seconds:
            self._invalid("access token has expired")
        if not set(claims.audiences()).intersection(expected_audiences):
            self._invalid("access token audience does not identify this resource server")

        return ValidatedAccessToken(
            claims=claims,
            key_id=key_id,
            algorithm=algorithm,
            token_type=token_type,
        )

    def _read_header(self, token: str) -> dict[str, Any]:
        """Parse only JOSE routing metadata before signature verification."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise ProtocolValidationError(
                "JWT access token header is malformed",
                code=INVALID_TOKEN_ERROR,
            ) from exc
        return dict(header)

    def _read_token_type(self, header: dict[str, Any]) -> str:
        """Enforce ``at+jwt`` to prevent cross-JWT confusion with ID tokens."""
        token_type = self._read_required_header_string(header, "typ")
        if token_type.lower() not in {item.lower() for item in self._policy.accepted_types}:
            self._invalid("JWT typ header is not an RFC 9068 access-token type")
        return token_type

    def _read_required_header_string(self, header: dict[str, Any], name: str) -> str:
        """Read a non-empty JOSE header string used in a security decision."""
        value = header.get(name)
        if not isinstance(value, str) or not value.strip():
            self._invalid(f"JWT header {name} must be a non-empty string")
        return value

    def _validate_size(self, token: str) -> None:
        """Reject oversized JWTs before parsing or cryptographic work."""
        if len(token.encode("utf-8")) > self._policy.maximum_token_bytes:
            self._invalid("JWT access token exceeds the configured size limit")

    @staticmethod
    def _invalid(message: str) -> NoReturn:
        """Raise the stable RFC 6750-compatible invalid-token error."""
        raise ProtocolValidationError(message, code=INVALID_TOKEN_ERROR)
