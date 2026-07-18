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

    Class responsibility
    -----------------------
    Defines immutable protocol data contracts and validation invariants.

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

    iss: str = Field(min_length=1, max_length=255)
    sub: str = Field(min_length=1, max_length=255)
    aud: str | tuple[str, ...]
    exp: int
    iat: int
    jti: str = Field(min_length=1, max_length=255)
    nbf: int | None = None

    @model_validator(mode="after")
    def validate_client_identity(self) -> ClientAssertionClaims:
        """Require one client identifier in both issuer and subject claims.

        Function responsibility
        -----------------------
        Defines immutable protocol data contracts and validation invariants.

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
        if self.iss != self.sub:
            raise ValueError("iss and sub must identify the same OAuth client")
        return self


class JwtAuthorizationGrantClaims(BaseModel):
    """Claims carried by a JWT used as an OAuth authorization grant.

    Class responsibility
    -----------------------
    Defines immutable protocol data contracts and validation invariants.

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

    model_config = ConfigDict(extra="allow", frozen=True)

    iss: str = Field(min_length=1, max_length=2048)
    sub: str = Field(min_length=1, max_length=2048)
    aud: str | tuple[str, ...]
    exp: int
    iat: int
    jti: str = Field(min_length=1, max_length=255)
    nbf: int | None = None


class ClientAuthenticationRequest(BaseModel):
    """OAuth token-endpoint parameters for JWT client authentication.

    Class responsibility
    -----------------------
    Defines immutable protocol data contracts and validation invariants.

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

    client_assertion_type: str = JWT_BEARER_ASSERTION_TYPE
    client_assertion: str = Field(min_length=1)
    client_id: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_assertion_type(self) -> ClientAuthenticationRequest:
        """Reject assertion types other than the RFC 7523 JWT bearer value.

        Function responsibility
        -----------------------
        Defines immutable protocol data contracts and validation invariants.

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
        if self.client_assertion_type != JWT_BEARER_ASSERTION_TYPE:
            raise ValueError("unsupported client_assertion_type")
        return self

    def to_form_fields(self) -> dict[str, str]:
        """Serialize this request into OAuth form parameters.

        Function responsibility
        -----------------------
        Defines immutable protocol data contracts and validation invariants.

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
        fields = {
            "client_assertion_type": self.client_assertion_type,
            "client_assertion": self.client_assertion,
        }
        if self.client_id is not None:
            fields["client_id"] = self.client_id
        return fields


class JwtAuthorizationGrantRequest(BaseModel):
    """OAuth token-endpoint parameters for a JWT bearer authorization grant.

    Class responsibility
    -----------------------
    Defines immutable protocol data contracts and validation invariants.

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

    grant_type: str = JWT_BEARER_GRANT_TYPE
    assertion: str = Field(min_length=1)
    scope: str | None = None

    @model_validator(mode="after")
    def validate_grant_type(self) -> JwtAuthorizationGrantRequest:
        """Reject grant types other than the RFC 7523 JWT bearer value.

        Function responsibility
        -----------------------
        Defines immutable protocol data contracts and validation invariants.

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
        if self.grant_type != JWT_BEARER_GRANT_TYPE:
            raise ValueError("unsupported grant_type")
        return self

    def to_form_fields(self) -> dict[str, str]:
        """Serialize this request into OAuth form parameters.

        Function responsibility
        -----------------------
        Defines immutable protocol data contracts and validation invariants.

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
        fields = {"grant_type": self.grant_type, "assertion": self.assertion}
        if self.scope is not None:
            fields["scope"] = self.scope
        return fields


class AuthenticatedClient(BaseModel):
    """Stable result returned after successful private-key JWT authentication.

    Class responsibility
    -----------------------
    Defines immutable protocol data contracts and validation invariants.

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

    client_id: str
    key_id: str
    algorithm: str
    assertion_id: str
    issued_at: datetime
    expires_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidatedAuthorizationGrant(BaseModel):
    """Validated RFC 7523 authorization-grant assertion context.

    Class responsibility
    -----------------------
    Defines immutable protocol data contracts and validation invariants.

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

    issuer: str
    subject: str
    key_id: str
    algorithm: str
    assertion_id: str
    issued_at: datetime
    expires_at: datetime
    claims: dict[str, Any]
