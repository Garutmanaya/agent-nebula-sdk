"""Typed RFC 7523 request, claim, and result models.

RFC references:
- RFC 7521, Section 4.2: assertion-based client authentication parameters.
- RFC 7521, Section 4.1: assertion authorization-grant parameters.
- RFC 7523, Sections 3 and 4: JWT claim and processing requirements.

The SDK profile deliberately requires ``iat`` and ``jti`` for replay control.
RFC 7523 permits deployment-specific requirements for these claims, and the
Agent Nebula profile chooses the stricter behavior needed for machine clients.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_nebula_sdk.oauth.rfc7523.constants import (
    JWT_BEARER_ASSERTION_TYPE,
    JWT_BEARER_GRANT_TYPE,
)


class ClientAssertionClaims(BaseModel):
    """Claims carried by a JWT used for OAuth client authentication.

    ``iss`` and ``sub`` identify the OAuth client. ``aud`` identifies the token
    endpoint. ``exp`` limits assertion lifetime, while ``jti`` enables atomic
    replay detection by the authorization server.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    iss: str = Field(min_length=1, max_length=255)
    sub: str = Field(min_length=1, max_length=255)
    aud: str | tuple[str, ...]
    exp: int
    iat: int
    jti: str = Field(min_length=1, max_length=255)
    nbf: int | None = None

    @model_validator(mode="after")
    def validate_client_identity(self) -> ClientAssertionClaims:
        """Require one client identifier in both issuer and subject claims."""
        if self.iss != self.sub:
            raise ValueError("iss and sub must identify the same OAuth client")
        return self


class JwtAuthorizationGrantClaims(BaseModel):
    """Claims carried by a JWT used as an OAuth authorization grant.

    RFC 7523 allows subject assertions to represent a resource owner or another
    authorized principal. The SDK validates syntax and cryptographic properties;
    the consuming authorization server remains responsible for mapping ``sub``
    to local authorization policy.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    iss: str = Field(min_length=1, max_length=2048)
    sub: str = Field(min_length=1, max_length=2048)
    aud: str | tuple[str, ...]
    exp: int
    iat: int
    jti: str = Field(min_length=1, max_length=255)
    nbf: int | None = None


class ClientAuthenticationRequest(BaseModel):
    """OAuth token-endpoint parameters for JWT client authentication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    client_assertion_type: str = JWT_BEARER_ASSERTION_TYPE
    client_assertion: str = Field(min_length=1)
    client_id: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_assertion_type(self) -> ClientAuthenticationRequest:
        """Reject assertion types other than the RFC 7523 JWT bearer value."""
        if self.client_assertion_type != JWT_BEARER_ASSERTION_TYPE:
            raise ValueError("unsupported client_assertion_type")
        return self

    def to_form_fields(self) -> dict[str, str]:
        """Serialize this request into OAuth form parameters."""
        fields = {
            "client_assertion_type": self.client_assertion_type,
            "client_assertion": self.client_assertion,
        }
        if self.client_id is not None:
            fields["client_id"] = self.client_id
        return fields


class JwtAuthorizationGrantRequest(BaseModel):
    """OAuth token-endpoint parameters for a JWT bearer authorization grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_type: str = JWT_BEARER_GRANT_TYPE
    assertion: str = Field(min_length=1)
    scope: str | None = None

    @model_validator(mode="after")
    def validate_grant_type(self) -> JwtAuthorizationGrantRequest:
        """Reject grant types other than the RFC 7523 JWT bearer value."""
        if self.grant_type != JWT_BEARER_GRANT_TYPE:
            raise ValueError("unsupported grant_type")
        return self

    def to_form_fields(self) -> dict[str, str]:
        """Serialize this request into OAuth form parameters."""
        fields = {"grant_type": self.grant_type, "assertion": self.assertion}
        if self.scope is not None:
            fields["scope"] = self.scope
        return fields


class AuthenticatedClient(BaseModel):
    """Stable result returned after successful private-key JWT authentication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    client_id: str
    key_id: str
    algorithm: str
    assertion_id: str
    issued_at: datetime
    expires_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidatedAuthorizationGrant(BaseModel):
    """Validated RFC 7523 authorization-grant assertion context."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str
    subject: str
    key_id: str
    algorithm: str
    assertion_id: str
    issued_at: datetime
    expires_at: datetime
    claims: dict[str, Any]
