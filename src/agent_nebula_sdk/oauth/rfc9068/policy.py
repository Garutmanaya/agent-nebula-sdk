"""Deployment policy for RFC 9068 token issuance and validation.

RFC 9068 requires RS256 support and prohibits ``none``. Deployments may add
other asymmetric algorithms, but the same explicit allowlist must be applied
by issuers and resource servers to prevent algorithm confusion.
"""

from __future__ import annotations

from datetime import timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_nebula_sdk.oauth.rfc9068.constants import (
    ACCESS_TOKEN_TYPE,
    APPLICATION_ACCESS_TOKEN_TYPE,
    REQUIRED_CLAIMS,
)


class Rfc9068Policy(BaseModel):
    """Define strict, reusable controls for JWT access-token processing.

    Responsibility
    --------------
    Keep cryptographic and temporal choices outside issuer and validator code,
    allowing future product profiles to be added without modifying RFC logic.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_algorithms: frozenset[str] = frozenset({"RS256", "ES256", "EdDSA"})
    accepted_types: frozenset[str] = frozenset({ACCESS_TOKEN_TYPE, APPLICATION_ACCESS_TOKEN_TYPE})
    token_lifetime: timedelta = timedelta(minutes=10)
    clock_skew: timedelta = timedelta(seconds=60)
    maximum_token_bytes: int = Field(default=16384, ge=1024, le=1048576)
    maximum_additional_claims: int = Field(default=32, ge=0, le=256)
    require_https_issuer: bool = True
    require_jti_uuid: bool = False
    permitted_private_claim_prefixes: tuple[str, ...] = (
        "https://agent-nebula.example/claims/",
        "urn:agent-nebula:claims:",
    )

    @field_validator("allowed_algorithms")
    @classmethod
    def validate_algorithms(cls, value: frozenset[str]) -> frozenset[str]:
        """Require RS256 interoperability and reject unsigned JWTs."""
        if "RS256" not in value:
            raise ValueError("RFC 9068 implementations must support RS256")
        if "none" in {algorithm.lower() for algorithm in value}:
            raise ValueError("the none algorithm is prohibited")
        if not value:
            raise ValueError("allowed_algorithms must not be empty")
        return value

    @model_validator(mode="after")
    def validate_time_policy(self) -> Rfc9068Policy:
        """Reject unsafe or nonsensical token timing configuration."""
        if self.token_lifetime <= timedelta(0):
            raise ValueError("token_lifetime must be positive")
        if self.clock_skew < timedelta(0):
            raise ValueError("clock_skew must not be negative")
        return self

    def is_registered_claim(self, name: str) -> bool:
        """Return whether a claim name is owned by RFC 9068 core semantics."""
        return name in REQUIRED_CLAIMS or name in {
            "scope",
            "auth_time",
            "acr",
            "amr",
            "groups",
            "roles",
            "entitlements",
            "cnf",
        }

    def permits_private_claim(self, name: str) -> bool:
        """Accept only collision-resistant private claim names.

        RFC 9068 Section 2.2.2 allows arbitrary attributes when names are
        collision resistant or tokens remain within a private subsystem.
        """
        return any(name.startswith(prefix) for prefix in self.permitted_private_claim_prefixes)
