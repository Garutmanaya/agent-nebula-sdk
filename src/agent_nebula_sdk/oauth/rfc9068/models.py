"""Typed contracts for RFC 9068 JWT access tokens.

RFC 9068 Section 2.2 requires ``iss``, ``sub``, ``aud``, ``exp``, ``iat``,
``jti``, and ``client_id``. Optional authentication and authorization claims
are modeled explicitly so product code does not pass unstructured dictionaries
through the security boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AccessTokenClaims(BaseModel):
    """Represent the validated RFC 9068 JWT claims set.

    Responsibility
    --------------
    Provide one immutable, typed representation shared by authorization-server
    issuance and resource-server validation.

    Standards
    ---------
    RFC 9068 Sections 2.2, 2.2.1, 2.2.2, and 2.2.3.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    iss: str = Field(min_length=1, max_length=2048)
    sub: str = Field(min_length=1, max_length=2048)
    aud: str | tuple[str, ...]
    exp: int
    iat: int
    jti: str = Field(min_length=1, max_length=512)
    client_id: str = Field(min_length=1, max_length=255)
    scope: str | None = Field(default=None, max_length=8192)
    auth_time: int | None = None
    acr: str | None = Field(default=None, max_length=512)
    amr: tuple[str, ...] | None = None
    groups: tuple[str, ...] | None = None
    roles: tuple[str, ...] | None = None
    entitlements: tuple[str, ...] | None = None
    cnf: dict[str, str] | None = None

    @field_validator("aud")
    @classmethod
    def validate_audience(cls, value: str | tuple[str, ...]) -> str | tuple[str, ...]:
        """Reject empty audience values before token issuance or acceptance.

        RFC 9068 Section 2.2 requires an ``aud`` claim. RFC 7519 permits either
        one string or an array; this model preserves both representations.
        """
        values = (value,) if isinstance(value, str) else value
        if not values or any(not item.strip() for item in values):
            raise ValueError("audience values must not be empty")
        if len(set(values)) != len(values):
            raise ValueError("audience values must not contain duplicates")
        return value

    @field_validator("amr", "groups", "roles", "entitlements")
    @classmethod
    def validate_string_collections(
        cls,
        value: tuple[str, ...] | None,
    ) -> tuple[str, ...] | None:
        """Reject blank or duplicate values in security-relevant claim arrays."""
        if value is None:
            return None
        if any(not item.strip() for item in value):
            raise ValueError("claim collections must not contain blank values")
        if len(set(value)) != len(value):
            raise ValueError("claim collections must not contain duplicates")
        return value

    @model_validator(mode="after")
    def validate_temporal_order(self) -> AccessTokenClaims:
        """Require expiration after issuance and authentication before issuance."""
        if self.exp <= self.iat:
            raise ValueError("exp must be later than iat")
        if self.auth_time is not None and self.auth_time > self.iat:
            raise ValueError("auth_time must not be later than iat")
        return self

    def audiences(self) -> tuple[str, ...]:
        """Return ``aud`` as a normalized tuple for resource-server checks."""
        return (self.aud,) if isinstance(self.aud, str) else self.aud


@dataclass(frozen=True, slots=True)
class AccessTokenSigningKey:
    """Carry authorization-server private signing material and JOSE metadata.

    Private key persistence remains product-owned. The SDK receives only the
    key object selected for the current issuance operation.
    """

    key_id: str
    algorithm: str
    private_key: object

    def __post_init__(self) -> None:
        """Reject incomplete key metadata before a token can be signed."""
        if not self.key_id.strip():
            raise ValueError("key_id must not be empty")
        if not self.algorithm.strip():
            raise ValueError("algorithm must not be empty")


class AccessTokenIssueRequest(BaseModel):
    """Describe all inputs required to issue one RFC 9068 access token.

    ``additional_claims`` is limited by issuer policy. Registered claims cannot
    be overwritten through this extension point.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid", frozen=True)

    issuer: str = Field(min_length=1, max_length=2048)
    subject: str = Field(min_length=1, max_length=2048)
    audience: str | tuple[str, ...]
    client_id: str = Field(min_length=1, max_length=255)
    scope: tuple[str, ...] = ()
    auth_time: int | None = None
    acr: str | None = None
    amr: tuple[str, ...] | None = None
    groups: tuple[str, ...] | None = None
    roles: tuple[str, ...] | None = None
    entitlements: tuple[str, ...] | None = None
    confirmation_jkt: str | None = Field(default=None, min_length=1, max_length=512)
    additional_claims: Mapping[str, Any] = Field(default_factory=dict)


class IssuedAccessToken(BaseModel):
    """Return a signed compact JWT and its normalized trusted claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: str
    token_type: str = "Bearer"
    expires_in: int = Field(gt=0)
    claims: AccessTokenClaims
    key_id: str
    algorithm: str


class ValidatedAccessToken(BaseModel):
    """Return a resource-server validation result safe for policy evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claims: AccessTokenClaims
    key_id: str
    algorithm: str
    token_type: str
