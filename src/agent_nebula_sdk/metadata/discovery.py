"""RFC 8414 and RFC 9728 metadata URL construction and retrieval.

Purpose
-------
Implement deterministic well-known URL construction, bounded JSON retrieval,
and resource-identifier validation for A2A and MCP clients.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ExternalServiceError, ProtocolValidationError
from agent_nebula_sdk.metadata.models import AuthorizationServerMetadata, ProtectedResourceMetadata
from agent_nebula_sdk.ports.http import HttpTransport


def authorization_server_metadata_url(issuer: str) -> str:
    """Build the RFC 8414 well-known URL using path insertion.

    For ``https://auth.example/tenant`` the result is
    ``https://auth.example/.well-known/oauth-authorization-server/tenant``.
    """
    parsed = urlsplit(issuer)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ProtocolValidationError(
            "issuer must be an absolute HTTPS URL",
            code="invalid_issuer",
        )
    if parsed.query or parsed.fragment:
        raise ProtocolValidationError(
            "issuer must not contain query or fragment components",
            code="invalid_issuer",
        )
    suffix = parsed.path.lstrip("/")
    path = "/.well-known/oauth-authorization-server"
    if suffix:
        path = f"{path}/{suffix}"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def protected_resource_metadata_urls(resource: str) -> tuple[str, ...]:
    """Build RFC 9728 path-specific and root well-known discovery candidates.

    The path-specific candidate is returned first. A duplicate root candidate
    is removed when the resource itself is already origin-rooted.
    """
    parsed = urlsplit(resource)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ProtocolValidationError(
            "resource must be an absolute HTTPS URL",
            code="invalid_resource",
        )
    if parsed.fragment:
        raise ProtocolValidationError(
            "resource must not contain a fragment",
            code="invalid_resource",
        )
    suffix = parsed.path.lstrip("/")
    path_specific = "/.well-known/oauth-protected-resource"
    if suffix:
        path_specific = f"{path_specific}/{suffix}"
    first = urlunsplit((parsed.scheme, parsed.netloc, path_specific, "", ""))
    root = urlunsplit(
        (parsed.scheme, parsed.netloc, "/.well-known/oauth-protected-resource", "", "")
    )
    return (first,) if first == root else (first, root)


class OAuthMetadataClient:
    """Retrieve and validate OAuth metadata through an injected HTTP transport.

    The client deliberately does not follow redirects itself. Redirect policy,
    TLS verification, DNS controls, and network egress restrictions belong to
    the configured transport and deployment environment.
    """

    def __init__(self, *, transport: HttpTransport, maximum_response_bytes: int = 262_144) -> None:
        """Configure the metadata client with a bounded response size."""
        if maximum_response_bytes <= 0:
            raise ValueError("maximum_response_bytes must be positive")
        self._transport = transport
        self._maximum_response_bytes = maximum_response_bytes

    def fetch_authorization_server(self, issuer: str) -> AuthorizationServerMetadata:
        """Fetch RFC 8414 metadata and verify the returned issuer exactly."""
        metadata = AuthorizationServerMetadata.model_validate(
            self._get_json(authorization_server_metadata_url(issuer))
        )
        if metadata.issuer != issuer:
            raise ProtocolValidationError(
                "authorization server metadata issuer mismatch",
                code="issuer_metadata_mismatch",
                details={"expected": issuer, "actual": metadata.issuer},
            )
        return metadata

    def fetch_protected_resource(
        self,
        resource: str,
        *,
        metadata_url: str | None = None,
    ) -> ProtectedResourceMetadata:
        """Fetch RFC 9728 metadata from an explicit or well-known location.

        When no explicit challenge URL is supplied, path-specific discovery is
        attempted before root discovery, matching current MCP requirements.
        """
        urls = (
            (metadata_url,)
            if metadata_url is not None
            else protected_resource_metadata_urls(resource)
        )
        last_error: ExternalServiceError | None = None
        for url in urls:
            try:
                metadata = ProtectedResourceMetadata.model_validate(self._get_json(url))
                metadata.validate_for_requested_resource(resource)
                return metadata
            except ExternalServiceError as exc:
                last_error = exc
                if exc.details.get("status_code") != 404:
                    raise
            except ValidationError as exc:
                raise ProtocolValidationError(
                    "protected resource metadata is invalid",
                    code="invalid_resource_metadata",
                    details={"error_count": exc.error_count()},
                ) from exc
        if last_error is not None:
            raise last_error
        raise ExternalServiceError(
            "protected resource metadata could not be retrieved",
            code="metadata_unavailable",
        )

    def _get_json(self, url: str) -> dict[str, object]:
        """Retrieve one JSON object with status, content-type, and size checks."""
        response = self._transport.get(url, headers={"Accept": "application/json"})
        if response.status_code != 200:
            raise ExternalServiceError(
                "metadata endpoint returned an unsuccessful status",
                code="metadata_http_error",
                details={"status_code": response.status_code, "url": url},
            )
        if len(response.body) > self._maximum_response_bytes:
            raise ExternalServiceError(
                "metadata response exceeds configured size limit",
                code="metadata_response_too_large",
                details={"url": url},
            )
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in {"application/json", "application/oauth-authz-server+json"}:
            raise ExternalServiceError(
                "metadata endpoint returned an unsupported content type",
                code="metadata_content_type_error",
                details={"content_type": content_type, "url": url},
            )
        try:
            payload = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalServiceError(
                "metadata endpoint returned invalid JSON",
                code="metadata_json_error",
                details={"url": url},
            ) from exc
        if not isinstance(payload, dict):
            raise ExternalServiceError(
                "metadata response must be a JSON object",
                code="metadata_json_error",
                details={"url": url},
            )
        return payload
