"""Integration tests for the transport-neutral RFC 7591 client."""

from __future__ import annotations

import json

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7591.client import DynamicClientRegistrationClient
from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata
from agent_nebula_sdk.ports.http import HttpResponse


class RecordingTransport:
    """Record POST calls and return a configured response."""

    def __init__(self, response: HttpResponse) -> None:
        """Store the response returned by each call."""
        self.response = response
        self.calls: list[tuple[str, dict[str, str], bytes]] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Reject unused GET calls in this test adapter."""
        raise AssertionError(f"unexpected GET {url} {headers}")

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResponse:
        """Record the RFC 7591 POST request."""
        self.calls.append((url, dict(headers or {}), body))
        return self.response


def metadata(rsa_public_jwk: dict[str, str]) -> ClientMetadata:
    """Create valid machine-client registration metadata."""
    return ClientMetadata.model_validate(
        {
            "client_name": "Parking Host",
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "jwks": {"keys": [rsa_public_jwk]},
        }
    )


def test_registration_client_sends_json_and_bearer_token(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Controlled registration sends standard headers and parses the response."""
    transport = RecordingTransport(
        HttpResponse(
            status_code=201,
            headers={"content-type": "application/json"},
            body=json.dumps(
                {
                    "client_id": "client-123",
                    "client_id_issued_at": 1784376000,
                    "token_endpoint_auth_method": "private_key_jwt",
                    "grant_types": ["client_credentials"],
                    "response_types": [],
                }
            ).encode(),
        )
    )
    client = DynamicClientRegistrationClient(
        endpoint="https://registry.example/oauth/register",
        transport=transport,
    )
    response = client.register(metadata(rsa_public_jwk), initial_access_token="bootstrap")
    assert response.client_id == "client-123"
    _, headers, body = transport.calls[0]
    assert headers["Authorization"] == "Bearer bootstrap"
    assert json.loads(body)["client_name"] == "Parking Host"


def test_registration_client_maps_oauth_error_response(
    rsa_public_jwk: dict[str, str],
) -> None:
    """RFC 7591 errors become stable SDK protocol errors."""
    transport = RecordingTransport(
        HttpResponse(
            status_code=400,
            headers={"content-type": "application/json"},
            body=b'{"error":"invalid_client_metadata","error_description":"bad metadata"}',
        )
    )
    client = DynamicClientRegistrationClient(
        endpoint="https://registry.example/oauth/register",
        transport=transport,
    )
    with pytest.raises(ProtocolValidationError) as error:
        client.register(metadata(rsa_public_jwk))
    assert error.value.code == "invalid_client_metadata"


def test_registration_client_rejects_non_https_endpoint() -> None:
    """Registration metadata and credentials must not be sent over cleartext HTTP."""
    transport = RecordingTransport(HttpResponse(status_code=500, headers={}, body=b"{}"))
    with pytest.raises(ValueError, match="must use HTTPS"):
        DynamicClientRegistrationClient(
            endpoint="http://registry.example/oauth/register",
            transport=transport,
        )


def test_registration_client_rejects_invalid_json(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Non-JSON endpoint responses are normalized as external-service failures."""
    from agent_nebula_sdk.core.errors import ExternalServiceError

    transport = RecordingTransport(HttpResponse(status_code=201, headers={}, body=b"not-json"))
    client = DynamicClientRegistrationClient(
        endpoint="https://registry.example/oauth/register",
        transport=transport,
    )
    with pytest.raises(ExternalServiceError) as error:
        client.register(metadata(rsa_public_jwk))
    assert error.value.code == "invalid_registration_json"


def test_registration_client_enforces_response_size(
    rsa_public_jwk: dict[str, str],
) -> None:
    """Oversized endpoint responses are rejected before JSON parsing."""
    from agent_nebula_sdk.core.errors import ExternalServiceError

    transport = RecordingTransport(HttpResponse(status_code=201, headers={}, body=b"{}"))
    client = DynamicClientRegistrationClient(
        endpoint="https://registry.example/oauth/register",
        transport=transport,
        maximum_response_bytes=1,
    )
    with pytest.raises(ExternalServiceError) as error:
        client.register(metadata(rsa_public_jwk))
    assert error.value.code == "registration_response_too_large"
