"""Authorization-server issuer for RFC 9068 JWT access tokens.

The issuer consumes the audience already resolved by RFC 8707. It does not
perform provider lookup, database access, or business authorization decisions.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import jwt
from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ProtocolValidationError, UnsupportedAlgorithmError
from agent_nebula_sdk.oauth.rfc9068.constants import ACCESS_TOKEN_TYPE
from agent_nebula_sdk.oauth.rfc9068.models import (
    AccessTokenClaims,
    AccessTokenIssueRequest,
    AccessTokenSigningKey,
    IssuedAccessToken,
)
from agent_nebula_sdk.oauth.rfc9068.policy import Rfc9068Policy
from agent_nebula_sdk.ports.clock import Clock


class JwtAccessTokenIssuer:
    """Issue signed access tokens conforming to RFC 9068.

    Responsibility
    --------------
    Construct mandatory claims, merge approved optional claims, and sign the
    compact JWT with the selected authorization-server key.

    Standards
    ---------
    RFC 9068 Sections 2 and 3; RFC 8725 Sections 3.1 and 3.11.
    """

    def __init__(
        self,
        *,
        clock: Clock,
        policy: Rfc9068Policy,
        token_id_factory: Callable[[], str] | None = None,
    ) -> None:
        """Inject deterministic time, policy, and token identifier generation."""
        self._clock = clock
        self._policy = policy
        self._token_id_factory = token_id_factory or (lambda: str(uuid4()))

    def issue(
        self,
        *,
        request: AccessTokenIssueRequest,
        signing_key: AccessTokenSigningKey,
    ) -> IssuedAccessToken:
        """Create and sign one RFC 9068 access token.

        The caller must supply an unambiguous audience, normally produced by
        ``ResourceResolutionService.resolve_single_audience`` from RFC 8707.
        """
        self._validate_issuer(request.issuer)
        self._validate_algorithm(signing_key.algorithm)
        self._validate_additional_claims(request.additional_claims)

        now = self._clock.now()
        expires_at = now + self._policy.token_lifetime
        token_id = self._token_id_factory()
        if self._policy.require_jti_uuid:
            self._validate_uuid_token_id(token_id)

        claims_data: dict[str, Any] = {
            "iss": request.issuer,
            "sub": request.subject,
            "aud": request.audience,
            "exp": int(expires_at.timestamp()),
            "iat": int(now.timestamp()),
            "jti": token_id,
            "client_id": request.client_id,
        }
        if request.scope:
            claims_data["scope"] = " ".join(request.scope)
        for name in ("auth_time", "acr", "amr", "groups", "roles", "entitlements"):
            value = getattr(request, name)
            if value is not None:
                claims_data[name] = value
        if request.confirmation_jkt is not None:
            # RFC 9449 Section 6 binds a DPoP access token to the client key
            # through the standard confirmation claim member ``cnf.jkt``.
            claims_data["cnf"] = {"jkt": request.confirmation_jkt}
        claims_data.update(dict(request.additional_claims))

        try:
            claims = AccessTokenClaims.model_validate(claims_data)
            token = jwt.encode(
                payload=claims.model_dump(exclude_none=True),
                key=cast(Any, signing_key.private_key),
                algorithm=signing_key.algorithm,
                headers={
                    "alg": signing_key.algorithm,
                    "kid": signing_key.key_id,
                    "typ": ACCESS_TOKEN_TYPE,
                },
            )
        except (ValidationError, TypeError, ValueError, jwt.PyJWTError) as exc:
            raise ProtocolValidationError(
                "JWT access token could not be issued",
                code="access_token_issuance_failed",
            ) from exc

        return IssuedAccessToken(
            token=token,
            expires_in=int(self._policy.token_lifetime.total_seconds()),
            claims=claims,
            key_id=signing_key.key_id,
            algorithm=signing_key.algorithm,
        )

    def _validate_algorithm(self, algorithm: str) -> None:
        """Enforce the shared asymmetric algorithm allowlist before signing."""
        if algorithm not in self._policy.allowed_algorithms:
            raise UnsupportedAlgorithmError(
                "access-token signing algorithm is not allowed",
                code="unsupported_access_token_algorithm",
                details={"algorithm": algorithm},
            )

    def _validate_issuer(self, issuer: str) -> None:
        """Require an absolute HTTPS issuer in the default security profile."""
        parsed = urlsplit(issuer)
        if not parsed.scheme or not parsed.netloc:
            raise ProtocolValidationError(
                "issuer must be an absolute URI",
                code="invalid_access_token_issuer",
            )
        if self._policy.require_https_issuer and parsed.scheme.lower() != "https":
            raise ProtocolValidationError(
                "issuer must use HTTPS",
                code="invalid_access_token_issuer",
            )

    def _validate_additional_claims(self, claims: object) -> None:
        """Prevent extension claims from overriding standardized semantics."""
        if not isinstance(claims, dict):
            claims = dict(cast(Any, claims))
        if len(claims) > self._policy.maximum_additional_claims:
            raise ProtocolValidationError(
                "too many additional access-token claims",
                code="too_many_access_token_claims",
            )
        for name in claims:
            if self._policy.is_registered_claim(name):
                raise ProtocolValidationError(
                    "additional claims must not override registered claims",
                    code="registered_claim_override",
                    details={"claim": name},
                )
            if not self._policy.permits_private_claim(name):
                raise ProtocolValidationError(
                    "additional claim name is not collision resistant",
                    code="invalid_private_claim_name",
                    details={"claim": name},
                )

    @staticmethod
    def _validate_uuid_token_id(token_id: str) -> None:
        """Optionally require UUID-form JWT IDs for product audit correlation."""
        try:
            UUID(token_id)
        except ValueError as exc:
            raise ProtocolValidationError(
                "jti must be a UUID under the active profile",
                code="invalid_access_token_jti",
            ) from exc
