"""RFC 8414 metadata retrieval through an injected HTTP transport."""

from __future__ import annotations

import json

from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ExternalServiceError, ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8414.discovery import (
    authorization_server_metadata_url,
    openid_configuration_urls,
)
from agent_nebula_sdk.oauth.rfc8414.models import AuthorizationServerMetadata
from agent_nebula_sdk.ports.http import HttpTransport


class AuthorizationServerMetadataClient:
    """Retrieve and validate RFC 8414 Authorization Server Metadata."""

    def __init__(self, *, transport: HttpTransport, maximum_response_bytes: int = 262_144) -> None:
        """Configure the client with transport and a bounded response size."""
        if maximum_response_bytes <= 0:
            raise ValueError("maximum_response_bytes must be positive")
        self._transport = transport
        self._maximum_response_bytes = maximum_response_bytes

    def fetch(self, issuer: str) -> AuthorizationServerMetadata:
        """Fetch RFC 8414 metadata and verify exact issuer equality."""
        return self._fetch_url(
            issuer=issuer,
            metadata_url=authorization_server_metadata_url(issuer),
        )

    def fetch_url(self, metadata_url: str) -> AuthorizationServerMetadata:
        """Fetch and validate metadata from an explicitly advertised RFC 8414 URL.

        This form is used by protocols such as A2A that publish the metadata URL
        directly instead of publishing only an issuer identifier.
        """
        try:
            return AuthorizationServerMetadata.model_validate(self._get_json(metadata_url))
        except ValidationError as exc:
            raise ProtocolValidationError(
                "authorization server metadata is invalid",
                code="invalid_authorization_server_metadata",
                details={"error_count": exc.error_count()},
            ) from exc

    def fetch_with_openid_fallback(self, issuer: str) -> AuthorizationServerMetadata:
        """Fetch RFC 8414 first and then OpenID discovery compatibility URLs."""
        candidates = (authorization_server_metadata_url(issuer), *openid_configuration_urls(issuer))
        last_error: ExternalServiceError | None = None
        for metadata_url in candidates:
            try:
                return self._fetch_url(issuer=issuer, metadata_url=metadata_url)
            except ExternalServiceError as exc:
                last_error = exc
                if exc.details.get("status_code") != 404:
                    raise
        if last_error is not None:
            raise last_error
        raise ExternalServiceError(
            "authorization server metadata could not be retrieved",
            code="metadata_unavailable",
        )

    def _fetch_url(self, *, issuer: str, metadata_url: str) -> AuthorizationServerMetadata:
        """Fetch and validate one metadata candidate."""
        try:
            metadata = AuthorizationServerMetadata.model_validate(self._get_json(metadata_url))
        except ValidationError as exc:
            raise ProtocolValidationError(
                "authorization server metadata is invalid",
                code="invalid_authorization_server_metadata",
                details={"error_count": exc.error_count()},
            ) from exc
        if metadata.issuer != issuer:
            raise ProtocolValidationError(
                "authorization server metadata issuer mismatch",
                code="issuer_metadata_mismatch",
                details={"expected": issuer, "actual": metadata.issuer},
            )
        return metadata

    def _get_json(self, url: str) -> dict[str, object]:
        """Retrieve a bounded JSON metadata document."""
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
        if content_type not in {"application/json", "application/oauth-authz-server+json"} and not (
            content_type.startswith("application/") and content_type.endswith("+json")
        ):
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
