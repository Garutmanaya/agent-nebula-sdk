"""Typed request and response models for RFC 7591 registration.

The models preserve unknown extension metadata as required by RFC 7591 Section
2 while validating the standard metadata members used by OAuth clients.
Product-specific extensions are therefore possible without modifying this
module, but extension acceptance remains under the configured registration
policy.
"""

from __future__ import annotations

from typing import Any, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_nebula_sdk.jose.jwks.models import JwkSet
from agent_nebula_sdk.oauth.rfc7591.constants import (
    GRANT_TYPE_AUTHORIZATION_CODE,
    GRANT_TYPE_IMPLICIT,
    RESPONSE_TYPE_CODE,
    RESPONSE_TYPE_TOKEN,
    TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC,
)

_STANDARD_METADATA_NAMES = frozenset(
    {
        "redirect_uris",
        "token_endpoint_auth_method",
        "grant_types",
        "response_types",
        "client_name",
        "client_uri",
        "logo_uri",
        "scope",
        "contacts",
        "tos_uri",
        "policy_uri",
        "jwks_uri",
        "jwks",
        "software_id",
        "software_version",
        "software_statement",
    }
)
_HUMAN_READABLE_METADATA_NAMES = frozenset(
    {"client_name", "client_uri", "logo_uri", "tos_uri", "policy_uri"}
)


class ClientMetadata(BaseModel):
    """Represent OAuth client metadata accepted by RFC 7591.

    Responsibility
    --------------
    Validate standard registration metadata while retaining extension members
    for policy-controlled profiles such as Agent Nebula service clients and
    provider agents.

    Standards
    ---------
    * RFC 7591, Section 2.
    * RFC 6749, Section 2.
    * RFC 7517, Section 5.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    redirect_uris: tuple[str, ...] = ()
    token_endpoint_auth_method: str = TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC
    grant_types: tuple[str, ...] | None = None
    response_types: tuple[str, ...] | None = None
    client_name: str | None = Field(default=None, min_length=1, max_length=255)
    client_uri: str | None = Field(default=None, max_length=2048)
    logo_uri: str | None = Field(default=None, max_length=2048)
    scope: str | None = Field(default=None, max_length=4096)
    contacts: tuple[str, ...] = ()
    tos_uri: str | None = Field(default=None, max_length=2048)
    policy_uri: str | None = Field(default=None, max_length=2048)
    jwks_uri: str | None = Field(default=None, max_length=2048)
    jwks: JwkSet | None = None
    software_id: str | None = Field(default=None, min_length=1, max_length=255)
    software_version: str | None = Field(default=None, min_length=1, max_length=255)
    software_statement: str | None = Field(default=None, min_length=1, max_length=32768)

    @model_validator(mode="after")
    def validate_metadata_consistency(self) -> Self:
        """Validate cross-field relationships defined by RFC 7591.

        RFC 7591 allows either ``jwks_uri`` or inline ``jwks`` but not both.
        It also defines default grant and response types when these fields are
        omitted. Redirect URI requirements are validated against the resulting
        grant and response types.
        """
        if self.jwks_uri is not None and self.jwks is not None:
            raise ValueError("jwks_uri and jwks are mutually exclusive")

        grants = self.effective_grant_types
        responses = self.effective_response_types
        if GRANT_TYPE_AUTHORIZATION_CODE in grants and RESPONSE_TYPE_CODE not in responses:
            raise ValueError("authorization_code grant requires code response type")
        if GRANT_TYPE_IMPLICIT in grants and RESPONSE_TYPE_TOKEN not in responses:
            raise ValueError("implicit grant requires token response type")
        if RESPONSE_TYPE_CODE in responses and GRANT_TYPE_AUTHORIZATION_CODE not in grants:
            raise ValueError("code response type requires authorization_code grant")
        if RESPONSE_TYPE_TOKEN in responses and GRANT_TYPE_IMPLICIT not in grants:
            raise ValueError("token response type requires implicit grant")

        requires_redirect_uri = bool(
            set(grants) & {GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT}
            or set(responses) & {RESPONSE_TYPE_CODE, RESPONSE_TYPE_TOKEN}
        )
        if requires_redirect_uri and not self.redirect_uris:
            raise ValueError("redirect_uris are required for redirect-based OAuth flows")

        for redirect_uri in self.redirect_uris:
            self._validate_redirect_uri(redirect_uri)
        for metadata_uri in (
            self.client_uri,
            self.logo_uri,
            self.tos_uri,
            self.policy_uri,
            self.jwks_uri,
        ):
            if metadata_uri is not None:
                self._validate_absolute_uri(metadata_uri)

        if (
            self.token_endpoint_auth_method == "private_key_jwt"
            and self.jwks_uri is None
            and self.jwks is None
        ):
            raise ValueError("private_key_jwt requires jwks_uri or inline jwks")

        return self

    @property
    def effective_grant_types(self) -> tuple[str, ...]:
        """Return RFC 7591 defaulted grant types.

        RFC 7591 Section 2 states that an omitted ``grant_types`` member
        defaults to ``authorization_code``.
        """
        if self.grant_types is not None:
            return self.grant_types
        return (GRANT_TYPE_AUTHORIZATION_CODE,)

    @property
    def effective_response_types(self) -> tuple[str, ...]:
        """Return RFC 7591 defaulted response types.

        RFC 7591 Section 2 states that an omitted ``response_types`` member
        defaults to ``code``.
        """
        if self.response_types is not None:
            return self.response_types
        return (RESPONSE_TYPE_CODE,)

    def standard_metadata(
        self,
        *,
        allowed_extension_names: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        """Serialize metadata using RFC defaults and configured extensions.

        RFC 7591 Section 2 requires an authorization server to ignore metadata
        it does not understand. Standard fields and localized human-readable
        fields are always understood. Product extensions are retained only
        when the active registration policy declares their names.
        """
        data = self.model_dump(exclude_none=True, mode="json")
        data["grant_types"] = list(self.effective_grant_types)
        data["response_types"] = list(self.effective_response_types)

        registered: dict[str, Any] = {}
        for name, value in data.items():
            localized_base = name.split("#", maxsplit=1)[0]
            is_localized_standard = "#" in name and localized_base in _HUMAN_READABLE_METADATA_NAMES
            if (
                name in _STANDARD_METADATA_NAMES
                or name in allowed_extension_names
                or is_localized_standard
            ):
                registered[name] = value
        return registered

    @staticmethod
    def _validate_redirect_uri(uri: str) -> None:
        """Reject redirect URIs that are relative or contain fragments.

        RFC 6749 Section 3.1.2 requires absolute redirect URIs and prohibits
        fragment components. Native-loopback exceptions remain a deployment
        policy concern and can be implemented by a metadata policy plugin.
        """
        ClientMetadata._validate_absolute_uri(uri)
        if urlsplit(uri).fragment:
            raise ValueError("redirect_uri must not contain a fragment")

    @staticmethod
    def _validate_absolute_uri(uri: str) -> None:
        """Require an absolute URI with a scheme and authority where applicable."""
        parsed = urlsplit(uri)
        if not parsed.scheme:
            raise ValueError("URI must be absolute")
        if parsed.scheme in {"http", "https"} and not parsed.netloc:
            raise ValueError("HTTP URI must include an authority")


class RegistrationRequest(BaseModel):
    """Wrap an RFC 7591 client registration request.

    Responsibility
    --------------
    Keep transport context separate from client metadata so open, controlled,
    and enterprise registration policies can inspect authorization context
    without changing the RFC data model.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    metadata: ClientMetadata
    initial_access_token: str | None = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    remote_address: str | None = None


class RegisteredClientRecord(BaseModel):
    """Represent the durable result of a successful registration.

    This model is persistence-neutral. Agent Nebula may store it in
    PostgreSQL, while tests and small deployments may use in-memory adapters.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    client_id: str = Field(min_length=1, max_length=255)
    client_id_issued_at: int | None = None
    client_secret: str | None = None
    client_secret_expires_at: int | None = None
    metadata: dict[str, Any]
    registration_method: str
    trust_status: str
    is_active: bool = True


class RegistrationResponse(BaseModel):
    """Represent the JSON response returned by an RFC 7591 endpoint."""

    model_config = ConfigDict(extra="allow", frozen=True)

    client_id: str = Field(min_length=1, max_length=255)
    client_id_issued_at: int | None = None
    client_secret: str | None = None
    client_secret_expires_at: int | None = None

    @classmethod
    def from_record(cls, record: RegisteredClientRecord) -> RegistrationResponse:
        """Create a standards-compatible response from a durable record."""
        payload = dict(record.metadata)
        payload.update(
            {
                "client_id": record.client_id,
                "client_id_issued_at": record.client_id_issued_at,
                "client_secret": record.client_secret,
                "client_secret_expires_at": record.client_secret_expires_at,
            }
        )
        return cls.model_validate(payload)


class RegistrationErrorResponse(BaseModel):
    """Represent an RFC 7591 Section 3.2.2 error response body."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    error: str
    error_description: str | None = None
