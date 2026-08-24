"""RFC 9728 OAuth 2.0 Protected Resource Metadata models."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agent_nebula_sdk.core.errors import ProtocolValidationError

BearerMethod = Literal["header", "body", "query"]


def _validate_https_url(value: str, *, field_name: str, allow_query: bool = True) -> str:
    """Validate an absolute HTTPS URL used by RFC 9728 metadata."""
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError(f"{field_name} must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field_name} must not contain user information")
    if parsed.fragment:
        raise ValueError(f"{field_name} must not contain a fragment")
    if not allow_query and parsed.query:
        raise ValueError(f"{field_name} must not contain a query component")
    return value


class ProtectedResourceMetadata(BaseModel):
    """Represent OAuth Protected Resource Metadata defined by RFC 9728."""

    model_config = ConfigDict(extra="allow", frozen=True)

    resource: str
    authorization_servers: tuple[str, ...] = ()
    jwks_uri: str | None = None
    scopes_supported: tuple[str, ...] = ()
    bearer_methods_supported: tuple[BearerMethod, ...] = ()
    resource_signing_alg_values_supported: tuple[str, ...] = ()
    resource_name: str | None = None
    resource_documentation: str | None = None
    resource_policy_uri: str | None = None
    resource_tos_uri: str | None = None
    tls_client_certificate_bound_access_tokens: bool = False
    authorization_details_types_supported: tuple[str, ...] = ()
    dpop_signing_alg_values_supported: tuple[str, ...] = ()
    dpop_bound_access_tokens_required: bool = False
    signed_metadata: str | None = None

    @field_validator(
        "resource",
        "jwks_uri",
        "resource_documentation",
        "resource_policy_uri",
        "resource_tos_uri",
    )
    @classmethod
    def validate_resource_urls(cls, value: str | None, info: Any) -> str | None:
        """Validate protected-resource identifiers and referenced HTTPS URLs."""
        if value is None:
            return None
        return _validate_https_url(value, field_name=info.field_name)

    @field_validator("authorization_servers")
    @classmethod
    def validate_authorization_servers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Validate every advertised Authorization Server identifier."""
        return tuple(
            _validate_https_url(value, field_name="authorization_servers", allow_query=False)
            for value in values
        )

    @field_validator("resource_signing_alg_values_supported")
    @classmethod
    def reject_none_resource_algorithm(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Enforce RFC 9728's prohibition on the ``none`` signing algorithm."""
        if "none" in values:
            raise ValueError("resource signing algorithms must not contain 'none'")
        return values

    @model_validator(mode="after")
    def require_dpop_algorithms_when_dpop_is_required(self) -> ProtectedResourceMetadata:
        """Require an advertised DPoP algorithm when DPoP-bound tokens are mandatory."""
        if self.dpop_bound_access_tokens_required and not self.dpop_signing_alg_values_supported:
            raise ValueError(
                "dpop_signing_alg_values_supported is required when DPoP-bound tokens are required"
            )
        return self

    def validate_for_requested_resource(self, requested_resource: str) -> None:
        """Require exact RFC 9728 resource-identifier matching."""
        if self.resource != requested_resource:
            raise ProtocolValidationError(
                "protected resource metadata does not match the requested resource",
                code="resource_metadata_mismatch",
                details={"expected": requested_resource, "actual": self.resource},
            )
