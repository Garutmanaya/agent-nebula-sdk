"""External-call tests for the HTTPX transport adapter."""

from __future__ import annotations

import httpx
import pytest
import respx

from agent_nebula_sdk.adapters.httpx_transport import HttpxTransport
from agent_nebula_sdk.core.errors import ExternalServiceError


@respx.mock
def test_httpx_transport_returns_normalized_response() -> None:
    """Successful external responses are mapped to the SDK response contract."""
    route = respx.get("https://client.example/jwks.json").mock(
        return_value=httpx.Response(200, json={"keys": []})
    )
    transport = HttpxTransport()

    response = transport.get("https://client.example/jwks.json")
    transport.close()

    assert route.called
    assert response.status_code == 200
    assert b"keys" in response.body


@respx.mock
def test_httpx_transport_normalizes_timeout() -> None:
    """Transport-specific timeouts never leak through the public SDK API."""
    respx.get("https://client.example/jwks.json").mock(side_effect=httpx.ReadTimeout("timeout"))
    transport = HttpxTransport(timeout_seconds=1)

    with pytest.raises(ExternalServiceError) as error:
        transport.get("https://client.example/jwks.json")

    transport.close()
    assert error.value.code == "http_transport_error"


def test_httpx_transport_rejects_non_positive_timeout() -> None:
    """A missing timeout is not permitted for security metadata retrieval."""
    with pytest.raises(ValueError):
        HttpxTransport(timeout_seconds=0)
