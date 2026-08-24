"""RFC 9728 Protected Resource Metadata retrieval client."""

from __future__ import annotations

import json

from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ExternalServiceError, ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9728.discovery import protected_resource_metadata_urls
from agent_nebula_sdk.oauth.rfc9728.models import ProtectedResourceMetadata
from agent_nebula_sdk.ports.http import HttpTransport


class ProtectedResourceMetadataClient:
    """Retrieve and validate RFC 9728 metadata through an injected transport."""

    def __init__(self, *, transport: HttpTransport, maximum_response_bytes: int = 262_144) -> None:
        """Configure transport and maximum accepted metadata-document size."""
        if maximum_response_bytes <= 0:
            raise ValueError("maximum_response_bytes must be positive")
        self._transport = transport
        self._maximum_response_bytes = maximum_response_bytes

    def fetch(
        self,
        resource: str,
        *,
        metadata_url: str | None = None,
    ) -> ProtectedResourceMetadata:
        """Fetch metadata from an explicit RFC 9728 URL or well-known candidates."""
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
        """Retrieve a bounded RFC 9728 JSON metadata document."""
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
        if content_type != "application/json" and not (
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
