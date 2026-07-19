"""HTTP resolver for OAuth Client ID Metadata Documents used by MCP."""

from __future__ import annotations

import json
import re
from datetime import timedelta

from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ExternalServiceError, ProtocolValidationError
from agent_nebula_sdk.mcp.client_id_metadata.cache import ClientIdMetadataCache
from agent_nebula_sdk.mcp.client_id_metadata.models import (
    ClientIdMetadataDocument,
    ResolvedClientIdMetadata,
)
from agent_nebula_sdk.mcp.client_id_metadata.policy import ClientIdMetadataPolicy
from agent_nebula_sdk.ports.http import HttpTransport

_MAX_AGE_PATTERN = re.compile(r"(?:^|,)\s*max-age=(\d+)\s*(?:,|$)", re.IGNORECASE)


class ClientIdMetadataResolver:
    """Fetch, validate, and cache URL-based MCP OAuth client metadata.

    Redirect handling is intentionally delegated to a transport configured not
    to follow redirects. This prevents an initially safe URL from redirecting
    to a private or otherwise disallowed network target.
    """

    def __init__(
        self,
        *,
        transport: HttpTransport,
        policy: ClientIdMetadataPolicy,
        cache: ClientIdMetadataCache | None = None,
        default_ttl: timedelta = timedelta(minutes=15),
        maximum_ttl: timedelta = timedelta(hours=24),
        maximum_response_bytes: int = 262_144,
    ) -> None:
        """Configure retrieval, security policy, caching, and response limits."""
        if default_ttl <= timedelta(0) or maximum_ttl <= timedelta(0):
            raise ValueError("metadata cache TTL values must be positive")
        if default_ttl > maximum_ttl:
            raise ValueError("default_ttl must not exceed maximum_ttl")
        if maximum_response_bytes <= 0:
            raise ValueError("maximum_response_bytes must be positive")
        self._transport = transport
        self._policy = policy
        self._cache = cache
        self._default_ttl = default_ttl
        self._maximum_ttl = maximum_ttl
        self._maximum_response_bytes = maximum_response_bytes

    def resolve(self, client_id: str, *, force_refresh: bool = False) -> ResolvedClientIdMetadata:
        """Resolve and validate one Client Identifier URL.

        Invalid documents and unsuccessful responses are never cached. Exact
        string equality is enforced between the requested URL and the
        document's ``client_id`` member.
        """
        self._policy.validate_client_id(client_id)
        if self._cache is not None and not force_refresh:
            cached = self._cache.get(client_id)
            if cached is not None:
                return cached

        response = self._transport.get(client_id, headers={"Accept": "application/json"})
        if response.status_code != 200:
            raise ExternalServiceError(
                "client metadata endpoint returned an unsuccessful status",
                code="client_metadata_http_error",
                details={"status_code": response.status_code, "client_id": client_id},
            )
        if len(response.body) > self._maximum_response_bytes:
            raise ExternalServiceError(
                "client metadata response exceeds configured size limit",
                code="client_metadata_response_too_large",
                details={"client_id": client_id},
            )
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json" and not (
            content_type.startswith("application/") and content_type.endswith("+json")
        ):
            raise ExternalServiceError(
                "client metadata endpoint returned an unsupported content type",
                code="client_metadata_content_type_error",
                details={"content_type": content_type, "client_id": client_id},
            )
        try:
            payload = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalServiceError(
                "client metadata endpoint returned invalid JSON",
                code="client_metadata_json_error",
                details={"client_id": client_id},
            ) from exc
        if not isinstance(payload, dict):
            raise ExternalServiceError(
                "client metadata document must be a JSON object",
                code="client_metadata_json_error",
                details={"client_id": client_id},
            )
        try:
            document = ClientIdMetadataDocument.model_validate(payload)
            resolved = ResolvedClientIdMetadata(
                document=document,
                source_url=client_id,
                etag=response.headers.get("etag"),
                last_modified=response.headers.get("last-modified"),
                cache_max_age_seconds=self._cache_max_age(response.headers.get("cache-control")),
            )
        except ValidationError as exc:
            raise ProtocolValidationError(
                "client metadata document is invalid",
                code="invalid_client_metadata_document",
                details={"error_count": exc.error_count(), "client_id": client_id},
            ) from exc
        self._policy.validate_document(document)

        if self._cache is not None and resolved.cache_max_age_seconds != 0:
            ttl = self._ttl_for(resolved.cache_max_age_seconds)
            self._cache.put(resolved, ttl=ttl)
        return resolved

    def _ttl_for(self, max_age_seconds: int | None) -> timedelta:
        """Select a bounded cache TTL from HTTP metadata or the configured default."""
        if max_age_seconds is None:
            return self._default_ttl
        return min(timedelta(seconds=max_age_seconds), self._maximum_ttl)

    @staticmethod
    def _cache_max_age(value: str | None) -> int | None:
        """Parse one non-negative Cache-Control max-age directive."""
        if value is None or "no-store" in value.lower():
            return 0 if value is not None else None
        match = _MAX_AGE_PATTERN.search(value)
        return int(match.group(1)) if match else None
