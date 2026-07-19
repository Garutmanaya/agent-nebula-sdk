"""Unit tests for A2A authenticated HTTP request preparation."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_nebula_sdk.a2a import A2AHttpSecurityClient
from agent_nebula_sdk.ports.http import HttpResponse


def test_client_builds_a2a_media_type_and_dpop_headers() -> None:
    """Attach A2A media types to headers produced by the OAuth facade."""
    oauth = Mock()
    oauth.build_protected_request.return_value = SimpleNamespace(
        headers={"Authorization": "DPoP token", "DPoP": "proof"}
    )
    transport = Mock()
    client = A2AHttpSecurityClient(oauth=oauth, transport=transport)
    request = client.build_request(
        endpoint="https://metro.example.com/a2a",
        access_token="token",
        dpop_key=Mock(),
        payload={"jsonrpc": "2.0", "method": "message/send", "id": "1"},
    )
    assert request.headers["Content-Type"] == "application/a2a+json"
    assert request.headers["DPoP"] == "proof"


def test_client_parses_json_response() -> None:
    """Parse a successful A2A JSON object response."""
    oauth = Mock()
    transport = Mock()
    transport.post.return_value = HttpResponse(
        status_code=200,
        headers={"content-type": "application/a2a+json"},
        body=b'{"jsonrpc":"2.0","result":{"status":"ok"}}',
    )
    client = A2AHttpSecurityClient(oauth=oauth, transport=transport)
    response = client.send(
        SimpleNamespace(
            endpoint="https://metro.example.com/a2a",
            headers={},
            body=b"{}",
        )
    )
    assert isinstance(response.payload, dict)


def test_client_rejects_invalid_json_response() -> None:
    """Normalize malformed A2A response bodies into an SDK error."""
    from agent_nebula_sdk.core.errors import ExternalServiceError

    transport = Mock()
    transport.post.return_value = HttpResponse(
        status_code=502,
        headers={"content-type": "application/a2a+json"},
        body=b"not-json",
    )
    client = A2AHttpSecurityClient(oauth=Mock(), transport=transport)
    with pytest.raises(ExternalServiceError):
        client.send(SimpleNamespace(endpoint="https://metro.example/a2a", headers={}, body=b"{}"))
