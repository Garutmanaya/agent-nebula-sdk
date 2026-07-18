"""Authorization-server validation service for RFC 7523 JWT bearer grants.

This module is included because RFC 7523 defines both client authentication and
an assertion authorization grant. Agent Nebula Phase 1 primarily uses client
authentication, but the grant implementation remains a complete, independently
pluggable protocol component.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_nebula_sdk.core.errors import ProtocolValidationError, ReplayDetectedError
from agent_nebula_sdk.oauth.rfc7523.models import (
    JwtAuthorizationGrantRequest,
    ValidatedAuthorizationGrant,
)
from agent_nebula_sdk.oauth.rfc7523.ports import (
    AssertionReplayStore,
    AuthorizationGrantKeyResolver,
)
from agent_nebula_sdk.oauth.rfc7523.validator import JwtAssertionValidator


class JwtAuthorizationGrantValidator:
    """Validate a JWT bearer assertion used as an OAuth authorization grant.

    Class responsibility
    -----------------------
    Implements the JWT bearer authorization-grant role independently from client authentication.

    Standards
    ---------
    * RFC 7523
    * RFC 7521
    * RFC 7519

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def __init__(
        self,
        *,
        keys: AuthorizationGrantKeyResolver,
        replay_store: AssertionReplayStore,
        validator: JwtAssertionValidator,
        accepted_audiences: tuple[str, ...],
    ) -> None:
        """Create a grant validator with explicit issuer-key and replay ports.

        Function responsibility
        -----------------------
        Implements the JWT bearer authorization-grant role independently from client authentication.

        Standards
        ---------
        * RFC 7523
        * RFC 7521
        * RFC 7519

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        if not accepted_audiences:
            raise ValueError("accepted_audiences must not be empty")
        self._keys = keys
        self._replay_store = replay_store
        self._validator = validator
        self._accepted_audiences = accepted_audiences

    def validate(self, request: JwtAuthorizationGrantRequest) -> ValidatedAuthorizationGrant:
        """Validate signature, claims, audience, lifetime, and replay status.

        Function responsibility
        -----------------------
        Implements the JWT bearer authorization-grant role independently from client authentication.

        Standards
        ---------
        * RFC 7523
        * RFC 7521
        * RFC 7519

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        untrusted_claims = self._validator.decode_unverified_claims(request.assertion)
        issuer = untrusted_claims.get("iss")
        if not isinstance(issuer, str) or not issuer:
            raise ProtocolValidationError(
                "authorization-grant assertion requires iss",
                code="missing_assertion_issuer",
            )
        key_id, algorithm = self._validator.read_unverified_header(request.assertion)
        public_key = self._keys.resolve_issuer_key(
            issuer=issuer,
            key_id=key_id,
            algorithm=algorithm,
        )
        verified = self._validator.verify_authorization_grant(
            assertion=request.assertion,
            public_jwk=public_key,
            accepted_audiences=self._accepted_audiences,
        )
        claims = verified.claims
        expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=UTC)
        consumed = self._replay_store.consume(
            namespace="rfc7523:authorization-grant",
            subject=str(claims["sub"]),
            assertion_id=str(claims["jti"]),
            expires_at=expires_at,
        )
        if not consumed:
            raise ReplayDetectedError(
                "authorization-grant assertion has already been used",
                code="assertion_replay_detected",
            )
        return ValidatedAuthorizationGrant(
            issuer=str(claims["iss"]),
            subject=str(claims["sub"]),
            key_id=verified.key_id,
            algorithm=verified.algorithm,
            assertion_id=str(claims["jti"]),
            issued_at=datetime.fromtimestamp(int(claims["iat"]), tz=UTC),
            expires_at=expires_at,
            claims=dict(claims),
        )
