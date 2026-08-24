"""RFC 8414 OAuth 2.0 Authorization Server Metadata models.

This module contains only RFC 8414 data structures plus standards extensions
registered for authorization-server metadata. Product policy and persistence
remain outside the SDK protocol model.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, field_validator


def _validate_https_url(value: str, *, field_name: str) -> str:
    """Validate a security-sensitive absolute HTTPS metadata URL."""
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError(f"{field_name} must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field_name} must not contain user information")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{field_name} must not contain query or fragment components")
    return value


class AuthorizationServerMetadata(BaseModel):
    """Represent OAuth Authorization Server Metadata defined by RFC 8414.

    The ``protected_resources`` member is the RFC 9728 extension registered in
    the RFC 8414 authorization-server metadata registry.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    issuer: str
    token_endpoint: str | None = None
    jwks_uri: str | None = None
    registration_endpoint: str | None = None
    response_types_supported: tuple[str, ...] = ()
    grant_types_supported: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    token_endpoint_auth_methods_supported: tuple[str, ...] = ()
    token_endpoint_auth_signing_alg_values_supported: tuple[str, ...] = ()
    dpop_signing_alg_values_supported: tuple[str, ...] = ()
    protected_resources: tuple[str, ...] = ()
    service_documentation: str | None = None
    client_id_metadata_document_supported: bool = False
    code_challenge_methods_supported: tuple[str, ...] = ()

    @field_validator(
        "issuer",
        "token_endpoint",
        "jwks_uri",
        "registration_endpoint",
        "service_documentation",
    )
    @classmethod
    def validate_urls(cls, value: str | None, info: Any) -> str | None:
        """Validate RFC 8414 issuer and endpoint URLs before use."""
        if value is None:
            return None
        return _validate_https_url(value, field_name=info.field_name)

    @field_validator("token_endpoint_auth_signing_alg_values_supported")
    @classmethod
    def reject_none_client_auth_algorithm(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Reject ``none`` for client-authentication signature algorithms."""
        if "none" in values:
            raise ValueError("client authentication algorithms must not contain 'none'")
        return values
