"""Synchronous HTTPX implementation of the SDK HTTP transport port."""

from __future__ import annotations

import httpx

from agent_nebula_sdk.core.errors import ExternalServiceError
from agent_nebula_sdk.ports.http import HttpResponse


class HttpxTransport:
    """Verified-TLS HTTP transport with explicit timeout and redirect policy."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        verify: bool | str = True,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Create a transport that never follows redirects automatically.

        Args:
            timeout_seconds: Total HTTP timeout applied by HTTPX.
            verify: TLS verification policy or CA bundle path.
            transport: Optional HTTPX transport for tests or custom networking.
        """
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._client = httpx.Client(
            timeout=timeout_seconds,
            verify=verify,
            follow_redirects=False,
            transport=transport,
        )

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Issue a GET request and normalize network failures."""
        try:
            response = self._client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise ExternalServiceError(
                "outbound HTTP request failed",
                code="http_transport_error",
                details={"exception_type": type(exc).__name__},
            ) from exc
        return HttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.content,
        )

    def close(self) -> None:
        """Release the underlying connection pool."""
        self._client.close()
