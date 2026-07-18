"""RFC 7523 JWT assertion builders for OAuth clients and grants.

RFC references:
- RFC 7523, Section 2.2: JWT used for client authentication.
- RFC 7523, Section 2.1: JWT used as an authorization grant.
- RFC 7523, Section 3: required JWT claims and signature requirements.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, cast
from uuid import uuid4

import jwt

from agent_nebula_sdk.core.errors import ProtocolValidationError, UnsupportedAlgorithmError
from agent_nebula_sdk.oauth.rfc7523.models import (
    ClientAssertionClaims,
    ClientAuthenticationRequest,
    JwtAuthorizationGrantClaims,
    JwtAuthorizationGrantRequest,
)
from agent_nebula_sdk.oauth.rfc7523.policy import Rfc7523Policy
from agent_nebula_sdk.oauth.rfc7523.ports import ClientSigningKey
from agent_nebula_sdk.ports.clock import Clock


class ClientAssertionBuilder:
    """Build signed ``private_key_jwt`` client-authentication assertions."""

    def __init__(
        self,
        *,
        clock: Clock,
        policy: Rfc7523Policy,
        assertion_id_factory: Callable[[], str] | None = None,
    ) -> None:
        """Create a deterministic, policy-driven client assertion builder."""
        self._clock = clock
        self._policy = policy
        self._assertion_id_factory = assertion_id_factory or (lambda: str(uuid4()))

    def build(
        self,
        *,
        client_id: str,
        token_endpoint: str,
        signing_key: ClientSigningKey,
        include_client_id_parameter: bool = True,
    ) -> ClientAuthenticationRequest:
        """Create an RFC 7523 assertion and token-endpoint request parameters."""
        self._validate_inputs(
            client_id=client_id,
            token_endpoint=token_endpoint,
            algorithm=signing_key.algorithm,
        )
        now = self._clock.now()
        expires_at = now + self._policy.assertion_lifetime
        claims = ClientAssertionClaims(
            iss=client_id,
            sub=client_id,
            aud=token_endpoint,
            iat=int(now.timestamp()),
            exp=int(expires_at.timestamp()),
            jti=self._assertion_id_factory(),
        )
        token = self._encode(
            claims=claims.model_dump(exclude_none=True),
            signing_key=signing_key,
        )
        return ClientAuthenticationRequest(
            client_assertion=token,
            client_id=client_id if include_client_id_parameter else None,
        )

    def _validate_inputs(self, *, client_id: str, token_endpoint: str, algorithm: str) -> None:
        """Validate assertion inputs before signing any data."""
        if not client_id.strip():
            raise ProtocolValidationError(
                "client_id must not be empty",
                code="invalid_client_id",
            )
        if not token_endpoint.startswith("https://"):
            raise ProtocolValidationError(
                "token endpoint audience must use HTTPS",
                code="invalid_token_endpoint_audience",
            )
        if algorithm not in self._policy.allowed_algorithms:
            raise UnsupportedAlgorithmError(
                "client assertion signing algorithm is not allowed",
                code="unsupported_client_assertion_algorithm",
                details={"algorithm": algorithm},
            )

    @staticmethod
    def _encode(*, claims: Mapping[str, Any], signing_key: ClientSigningKey) -> str:
        """Sign a JWT while explicitly setting ``kid``, ``alg``, and ``typ``."""
        try:
            return jwt.encode(
                payload=dict(claims),
                key=cast(Any, signing_key.private_key),
                algorithm=signing_key.algorithm,
                headers={
                    "alg": signing_key.algorithm,
                    "kid": signing_key.key_id,
                    "typ": "JWT",
                },
            )
        except (TypeError, ValueError, jwt.PyJWTError) as exc:
            raise ProtocolValidationError(
                "client assertion could not be signed",
                code="client_assertion_signing_failed",
            ) from exc


class JwtAuthorizationGrantBuilder:
    """Build signed JWT bearer authorization-grant assertions."""

    def __init__(
        self,
        *,
        clock: Clock,
        policy: Rfc7523Policy,
        assertion_id_factory: Callable[[], str] | None = None,
    ) -> None:
        """Create a deterministic authorization-grant assertion builder."""
        self._clock = clock
        self._policy = policy
        self._assertion_id_factory = assertion_id_factory or (lambda: str(uuid4()))

    def build(
        self,
        *,
        issuer: str,
        subject: str,
        audience: str,
        signing_key: ClientSigningKey,
        scope: str | None = None,
        additional_claims: Mapping[str, Any] | None = None,
    ) -> JwtAuthorizationGrantRequest:
        """Create an RFC 7523 authorization-grant request."""
        if signing_key.algorithm not in self._policy.allowed_algorithms:
            raise UnsupportedAlgorithmError(
                "authorization-grant signing algorithm is not allowed",
                code="unsupported_grant_assertion_algorithm",
                details={"algorithm": signing_key.algorithm},
            )
        now = self._clock.now()
        expires_at = now + self._policy.assertion_lifetime
        claims: dict[str, Any] = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": self._assertion_id_factory(),
        }
        for name, value in (additional_claims or {}).items():
            if name in claims:
                raise ProtocolValidationError(
                    "additional claims must not override registered assertion claims",
                    code="reserved_claim_override",
                    details={"claim": name},
                )
            claims[name] = value
        validated = JwtAuthorizationGrantClaims.model_validate(claims)
        token = ClientAssertionBuilder._encode(
            claims=validated.model_dump(exclude_none=True),
            signing_key=signing_key,
        )
        return JwtAuthorizationGrantRequest(assertion=token, scope=scope)
