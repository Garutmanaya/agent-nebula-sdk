"""RFC 7523 JWT parsing, signature verification, and claims validation.

The validator intentionally separates structural parsing, key resolution,
cryptographic verification, temporal checks, and replay consumption. This
ordering prevents untrusted claims from being used before the signature is
validated and keeps each security decision independently testable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, TypeVar

import jwt
from pydantic import BaseModel, ConfigDict, ValidationError

from agent_nebula_sdk.core.errors import (
    ProtocolValidationError,
    UnsupportedAlgorithmError,
)
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk
from agent_nebula_sdk.oauth.rfc7523.models import (
    ClientAssertionClaims,
    JwtAuthorizationGrantClaims,
)
from agent_nebula_sdk.oauth.rfc7523.policy import Rfc7523Policy
from agent_nebula_sdk.ports.clock import Clock

_ClaimsModel = TypeVar("_ClaimsModel", bound=BaseModel)


class VerifiedJwtAssertion(BaseModel):
    """Cryptographically verified JWT assertion plus JOSE header metadata.

    Class responsibility
    -----------------------
    Validates untrusted protocol input and returns only normalized, trusted output.

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

    model_config = ConfigDict(extra="forbid", frozen=True)

    header: dict[str, Any]
    claims: dict[str, Any]
    key_id: str
    algorithm: str


class JwtAssertionValidator:
    """Validate signed JWT assertions according to the RFC 7523 profile.

    Class responsibility
    -----------------------
    Validates untrusted protocol input and returns only normalized, trusted output.

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

    def __init__(self, *, clock: Clock, policy: Rfc7523Policy) -> None:
        """Create a validator with injectable time and explicit security policy.

        Function responsibility
        -----------------------
        Validates untrusted protocol input and returns only normalized, trusted output.

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
        self._clock = clock
        self._policy = policy

    def read_unverified_header(self, assertion: str) -> tuple[str, str]:
        """Read only ``kid`` and ``alg`` before resolving the verification key.

        Function responsibility
        -----------------------
        Validates untrusted protocol input and returns only normalized, trusted output.

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
        self._validate_compact_size(assertion)
        try:
            header = jwt.get_unverified_header(assertion)
        except jwt.PyJWTError as exc:
            raise ProtocolValidationError(
                "JWT assertion header is malformed",
                code="malformed_assertion_header",
            ) from exc
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if not isinstance(algorithm, str) or not algorithm:
            raise ProtocolValidationError(
                "JWT assertion header requires alg",
                code="missing_assertion_algorithm",
            )
        if algorithm not in self._policy.allowed_algorithms:
            raise UnsupportedAlgorithmError(
                "JWT assertion algorithm is not allowed",
                code="unsupported_assertion_algorithm",
                details={"algorithm": algorithm},
            )
        if self._policy.require_kid and (not isinstance(key_id, str) or not key_id):
            raise ProtocolValidationError(
                "JWT assertion header requires kid",
                code="missing_assertion_key_id",
            )
        return str(key_id or ""), algorithm

    def decode_unverified_claims(self, assertion: str) -> dict[str, Any]:
        """Read untrusted claims only to locate a client or issuer record.

        Function responsibility
        -----------------------
        Validates untrusted protocol input and returns only normalized, trusted output.

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
        self._validate_compact_size(assertion)
        try:
            claims = jwt.decode(
                assertion,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise ProtocolValidationError(
                "JWT assertion payload is malformed",
                code="malformed_assertion_payload",
            ) from exc
        if not isinstance(claims, dict):
            raise ProtocolValidationError(
                "JWT assertion payload must be a JSON object",
                code="malformed_assertion_payload",
            )
        return claims

    def _validate_compact_size(self, assertion: str) -> None:
        """Reject oversized compact JWTs before JSON or cryptographic processing.

        Function responsibility
        -----------------------
        Validates untrusted protocol input and returns only normalized, trusted output.

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
        if len(assertion.encode("utf-8")) > self._policy.maximum_assertion_bytes:
            raise ProtocolValidationError(
                "JWT assertion exceeds the configured size limit",
                code="assertion_too_large",
                details={"maximum_bytes": self._policy.maximum_assertion_bytes},
            )

    def verify_client_assertion(
        self,
        *,
        assertion: str,
        public_jwk: SupportedPublicJwk,
        accepted_audiences: Sequence[str],
    ) -> VerifiedJwtAssertion:
        """Verify a client-authentication assertion and required claims.

        Function responsibility
        -----------------------
        Validates untrusted protocol input and returns only normalized, trusted output.

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
        return self._verify(
            assertion=assertion,
            public_jwk=public_jwk,
            accepted_audiences=accepted_audiences,
            claims_model=ClientAssertionClaims,
        )

    def verify_authorization_grant(
        self,
        *,
        assertion: str,
        public_jwk: SupportedPublicJwk,
        accepted_audiences: Sequence[str],
    ) -> VerifiedJwtAssertion:
        """Verify a JWT bearer authorization-grant assertion.

        Function responsibility
        -----------------------
        Validates untrusted protocol input and returns only normalized, trusted output.

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
        return self._verify(
            assertion=assertion,
            public_jwk=public_jwk,
            accepted_audiences=accepted_audiences,
            claims_model=JwtAuthorizationGrantClaims,
        )

    def _verify(
        self,
        *,
        assertion: str,
        public_jwk: SupportedPublicJwk,
        accepted_audiences: Sequence[str],
        claims_model: type[_ClaimsModel],
    ) -> VerifiedJwtAssertion:
        """Perform signature, claim presence, audience, and temporal validation.

        Function responsibility
        -----------------------
        Validates untrusted protocol input and returns only normalized, trusted output.

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
        # JOSE header inspection is intentionally limited to key selection metadata.
        # Claims remain untrusted until the signature has been verified.
        key_id, algorithm = self.read_unverified_header(assertion)
        if public_jwk.alg is not None and public_jwk.alg != algorithm:
            raise ProtocolValidationError(
                "assertion algorithm does not match the registered JWK",
                code="assertion_algorithm_key_mismatch",
            )
        # RFC 7523 requires issuer, subject, audience, and expiration. The active
        # profile may strengthen the baseline by requiring iat and jti.
        required_claims = ["iss", "sub", "aud", "exp"]
        if self._policy.require_iat:
            required_claims.append("iat")
        if self._policy.require_jti:
            required_claims.append("jti")
        try:
            decoded = jwt.decode_complete(
                assertion,
                key=public_jwk.to_public_key(),
                algorithms=[algorithm],
                audience=list(accepted_audiences),
                options={
                    "require": required_claims,
                    "verify_signature": True,
                    "verify_aud": True,
                    # Temporal validation is performed below with the injected
                    # Clock so tests and products do not depend on process time.
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.InvalidAudienceError as exc:
            raise ProtocolValidationError(
                "JWT assertion audience is not accepted",
                code="invalid_assertion_audience",
            ) from exc
        except jwt.MissingRequiredClaimError as exc:
            raise ProtocolValidationError(
                "JWT assertion is missing a required claim",
                code="missing_assertion_claim",
                details={"claim": exc.claim},
            ) from exc
        except jwt.InvalidIssuedAtError as exc:
            raise ProtocolValidationError(
                "JWT assertion iat claim is invalid",
                code="invalid_assertion_iat",
            ) from exc
        except jwt.InvalidSignatureError as exc:
            raise ProtocolValidationError(
                "JWT assertion signature is invalid",
                code="invalid_assertion_signature",
            ) from exc
        except jwt.PyJWTError as exc:
            raise ProtocolValidationError(
                "JWT assertion failed JOSE validation",
                code="invalid_assertion",
            ) from exc
        payload = decoded.get("payload")
        header = decoded.get("header")
        if not isinstance(payload, dict) or not isinstance(header, dict):
            raise ProtocolValidationError(
                "JWT library returned an invalid decoded structure",
                code="invalid_assertion",
            )
        try:
            validated_claims = claims_model.model_validate(payload)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "JWT assertion claims violate the RFC 7523 profile",
                code="invalid_assertion_claims",
                details={"errors": exc.errors(include_url=False)},
            ) from exc
        # PyJWT temporal checks are disabled above so all time decisions use the
        # injected Clock and remain deterministic across products and tests.
        self._validate_temporal_profile(validated_claims.model_dump())
        return VerifiedJwtAssertion(
            header=header,
            claims=validated_claims.model_dump(),
            key_id=key_id,
            algorithm=algorithm,
        )

    def _validate_temporal_profile(self, claims: Mapping[str, Any]) -> None:
        """Enforce expiration, not-before, maximum lifetime, and clock skew.

        Function responsibility
        -----------------------
        Validates untrusted protocol input and returns only normalized, trusted output.

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
        now = self._clock.now()
        skew = self._policy.clock_skew
        issued_at = datetime.fromtimestamp(int(claims["iat"]), tz=UTC)
        expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=UTC)
        not_before_value = claims.get("nbf")
        not_before = (
            datetime.fromtimestamp(int(not_before_value), tz=UTC)
            if not_before_value is not None
            else None
        )
        if expires_at <= issued_at:
            raise ProtocolValidationError(
                "JWT assertion exp must be later than iat",
                code="invalid_assertion_lifetime",
            )
        if expires_at - issued_at > self._policy.maximum_assertion_lifetime:
            raise ProtocolValidationError(
                "JWT assertion lifetime exceeds authorization-server policy",
                code="assertion_lifetime_too_long",
            )
        if issued_at > now + skew:
            raise ProtocolValidationError(
                "JWT assertion iat is too far in the future",
                code="assertion_issued_in_future",
            )
        if expires_at <= now - skew:
            raise ProtocolValidationError(
                "JWT assertion has expired",
                code="expired_assertion",
            )
        if not_before is not None and not_before > now + skew:
            raise ProtocolValidationError(
                "JWT assertion is not yet valid",
                code="assertion_not_yet_valid",
            )
