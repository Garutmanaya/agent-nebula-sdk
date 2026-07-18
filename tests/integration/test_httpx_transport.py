"""External-call tests for the HTTPX transport adapter."""

from __future__ import annotations

import httpx
import pytest

from agent_nebula_sdk.adapters.httpx_transport import HttpxTransport
from agent_nebula_sdk.core.errors import ExternalServiceError


def test_httpx_transport_returns_normalized_response() -> None:
    """Successful external responses are mapped to the SDK response contract."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Return one deterministic JWKS response and validate request details."""
        assert request.method == "GET"
        assert str(request.url) == "https://client.example/jwks.json"
        return httpx.Response(200, json={"keys": []})

    transport = HttpxTransport(transport=httpx.MockTransport(handler))

    response = transport.get("https://client.example/jwks.json")
    transport.close()

    assert response.status_code == 200
    assert b"keys" in response.body


def test_httpx_transport_normalizes_timeout() -> None:
    """Transport-specific timeouts never leak through the public SDK API."""

    def handler(_request: httpx.Request) -> httpx.Response:
        """Simulate a timeout raised by the underlying HTTP client."""
        raise httpx.ReadTimeout("timeout")

    transport = HttpxTransport(
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ExternalServiceError) as error:
        transport.get("https://client.example/jwks.json")

    transport.close()
    assert error.value.code == "http_transport_error"


def test_httpx_transport_does_not_follow_redirects() -> None:
    """Security metadata retrieval never follows an unvalidated redirect target."""

    def handler(_request: httpx.Request) -> httpx.Response:
        """Return a redirect that the adapter must expose rather than follow."""
        return httpx.Response(302, headers={"location": "https://other.example/jwks"})

    transport = HttpxTransport(transport=httpx.MockTransport(handler))

    response = transport.get("https://client.example/jwks.json")
    transport.close()

    assert response.status_code == 302


def test_httpx_transport_rejects_non_positive_timeout() -> None:
    """A missing timeout is not permitted for security metadata retrieval."""
    with pytest.raises(ValueError):
        HttpxTransport(timeout_seconds=0)
