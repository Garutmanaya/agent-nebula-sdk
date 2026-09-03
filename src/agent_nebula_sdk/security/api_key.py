"""Generic API-key extraction and verification."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from urllib.parse import parse_qs, urlsplit

from agent_nebula_sdk.core.errors import ProtocolValidationError

from .models import AuthenticatedIdentity


class ApiKeyCredentialVerifier(Protocol):
    """Product-owned verifier for opaque API-key values."""

    def verify(self, credential: str) -> AuthenticatedIdentity:
        """Verify the opaque API key and return a trusted identity."""
        ...


@dataclass(frozen=True, slots=True)
class ApiKeyRequest:
    """Transport data required to locate an API key."""

    headers: dict[str, str]
    target_uri: str


class ApiKeyAuthenticator:
    """Extract API keys from header, query, or cookie locations."""

    def __init__(self, verifier: ApiKeyCredentialVerifier) -> None:
        """Configure the product-owned opaque-key verifier."""
        self._verifier = verifier

    def authenticate(
        self,
        *,
        request: ApiKeyRequest,
        location: str,
        name: str,
    ) -> AuthenticatedIdentity:
        """Extract and verify the API key declared by the caller's protocol schema."""
        credential = self._extract(request=request, location=location, name=name)
        if not credential:
            raise ProtocolValidationError("API key is missing", code="invalid_api_key")
        return self._verifier.verify(credential)

    @staticmethod
    def _extract(*, request: ApiKeyRequest, location: str, name: str) -> str | None:
        """Extract exactly one credential from the configured request location."""
        if location == "header":
            return request.headers.get(name.lower())
        if location == "query":
            values = parse_qs(
                urlsplit(request.target_uri).query,
                keep_blank_values=True,
            ).get(name, [])
            return values[0] if len(values) == 1 else None
        if location == "cookie":
            raw = request.headers.get("cookie", "")
            for item in raw.split(";"):
                key, sep, value = item.strip().partition("=")
                if sep and key == name:
                    return value
            return None
        raise ProtocolValidationError(
            "unsupported API-key location",
            code="unsupported_api_key_location",
        )
