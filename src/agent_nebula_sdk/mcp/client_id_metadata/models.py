"""Typed OAuth Client ID Metadata Document models for current MCP profiles.

Purpose
-------
Represent URL-based OAuth client identities without using RFC 7591 Dynamic
Client Registration in the MCP integration path.

Standards
---------
* MCP Authorization specification, 2025-11-25.
* OAuth Client ID Metadata Document Internet-Draft.
* RFC 7591 client metadata registry members.
"""

from __future__ import annotations

from typing import Any, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_nebula_sdk.jose.jwks.models import JwkSet


class ClientIdMetadataDocument(BaseModel):
    """Represent one fetched Client ID Metadata Document.

    The document is intentionally distinct from an RFC 7591 registration
    record. Its ``client_id`` is the HTTPS URL from which this document was
    fetched, and the authorization server validates that identity by exact
    string comparison.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    client_id: str = Field(min_length=1, max_length=2048)
    client_name: str = Field(min_length=1, max_length=255)
    redirect_uris: tuple[str, ...] = Field(min_length=1)
    client_uri: str | None = Field(default=None, max_length=2048)
    logo_uri: str | None = Field(default=None, max_length=2048)
    grant_types: tuple[str, ...] = ("authorization_code",)
    response_types: tuple[str, ...] = ("code",)
    token_endpoint_auth_method: str = "none"
    scope: str | None = Field(default=None, max_length=4096)
    contacts: tuple[str, ...] = ()
    tos_uri: str | None = Field(default=None, max_length=2048)
    policy_uri: str | None = Field(default=None, max_length=2048)
    jwks_uri: str | None = Field(default=None, max_length=2048)
    jwks: JwkSet | None = None

    @model_validator(mode="after")
    def validate_document_consistency(self) -> Self:
        """Validate key-source, response-type, and redirect metadata.

        The current MCP profile requires authorization-code clients to publish
        redirect URIs. Public clients use ``none`` while confidential clients
        may use ``private_key_jwt`` with either inline JWKS or ``jwks_uri``.
        """
        validate_client_identifier_url(self.client_id, allow_query=True)
        if self.jwks_uri is not None and self.jwks is not None:
            raise ValueError("jwks_uri and jwks are mutually exclusive")
        if (
            self.token_endpoint_auth_method == "private_key_jwt"
            and self.jwks_uri is None
            and self.jwks is None
        ):
            raise ValueError("private_key_jwt requires jwks_uri or inline jwks")
        if "authorization_code" in self.grant_types and "code" not in self.response_types:
            raise ValueError("authorization_code grant requires code response type")
        if "code" in self.response_types and "authorization_code" not in self.grant_types:
            raise ValueError("code response type requires authorization_code grant")
        return self

    def extension_metadata(self) -> dict[str, Any]:
        """Return unknown extension members preserved by Pydantic."""
        known = set(type(self).model_fields)
        return {name: value for name, value in self.model_dump().items() if name not in known}


class ResolvedClientIdMetadata(BaseModel):
    """Expose a validated document with retrieval metadata for cache/audit use."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    document: ClientIdMetadataDocument
    source_url: str
    etag: str | None = None
    last_modified: str | None = None
    cache_max_age_seconds: int | None = None

    @model_validator(mode="after")
    def require_exact_document_identity(self) -> Self:
        """Require exact equality between the URL and document ``client_id``."""
        if self.document.client_id != self.source_url:
            raise ValueError("client_id must exactly match the metadata document URL")
        return self


def validate_client_identifier_url(client_id: str, *, allow_query: bool = False) -> str:
    """Validate the URL form required for a Client Identifier URL.

    The comparison value is returned unchanged because the specification uses
    simple string comparison and does not permit URL canonicalization to make
    two distinct identifiers equivalent.
    """
    parsed = urlsplit(client_id)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("client_id must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("client_id must not contain user information")
    if not parsed.path or parsed.path == "/":
        raise ValueError("client_id must contain a non-root path component")
    segments = parsed.path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise ValueError("client_id must not contain dot path components")
    if parsed.query and not allow_query:
        raise ValueError("client_id query components are not allowed by policy")
    if parsed.fragment:
        raise ValueError("client_id must not contain a fragment")
    return client_id
