"""Deployment policy for RFC 9449 DPoP proof processing.

RFC 9449 defines the protocol mechanics while deployments choose bounded proof
age, accepted asymmetric algorithms, nonce requirements, and URI comparison
strictness. The immutable policy keeps those decisions outside validators.
"""

from __future__ import annotations

from datetime import timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Rfc9449Policy(BaseModel):
    """Define reusable DPoP algorithm, timing, URI, and replay controls."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_algorithms: frozenset[str] = frozenset({"ES256", "RS256", "EdDSA"})
    maximum_proof_age: timedelta = timedelta(minutes=5)
    clock_skew: timedelta = timedelta(seconds=30)
    maximum_proof_bytes: int = Field(default=16384, ge=1024, le=1048576)
    require_https_target: bool = True
    require_nonce: bool = False
    require_ath_for_resource_request: bool = True
    reject_uri_fragments: bool = True

    @field_validator("allowed_algorithms")
    @classmethod
    def validate_algorithms(cls, value: frozenset[str]) -> frozenset[str]:
        """Allow only explicit asymmetric algorithms and reject ``none``."""
        if not value:
            raise ValueError("allowed_algorithms must not be empty")
        if "none" in {item.lower() for item in value}:
            raise ValueError("the none algorithm is prohibited for DPoP")
        return value

    @model_validator(mode="after")
    def validate_time_limits(self) -> Rfc9449Policy:
        """Reject non-positive proof age and negative clock skew settings."""
        if self.maximum_proof_age <= timedelta(0):
            raise ValueError("maximum_proof_age must be positive")
        if self.clock_skew < timedelta(0):
            raise ValueError("clock_skew must not be negative")
        return self
