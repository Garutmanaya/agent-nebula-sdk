"""Unit tests for server-side A2A request authentication."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from agent_nebula_sdk.a2a import A2ARequestAuthenticator
from agent_nebula_sdk.core.errors import ClientAuthenticationError


def test_authenticator_delegates_dpop_request_to_resource_server() -> None:
    """Extract headers and delegate exact request data to the role facade."""
    resource_server = Mock()
    resource_server.authenticate_request.return_value = object()
    authenticator = A2ARequestAuthenticator(resource_server=resource_server)
    result = authenticator.authenticate(
        headers={"Authorization": "DPoP access-token", "DPoP": "proof"},
        http_method="POST",
        target_uri="https://metro.example.com/a2a",
        expected_issuer="https://nebula.example.com",
    )
    assert result is resource_server.authenticate_request.return_value
    resource_server.authenticate_request.assert_called_once_with(
        access_token="access-token",
        dpop_proof="proof",
        http_method="POST",
        target_uri="https://metro.example.com/a2a",
        expected_issuer="https://nebula.example.com",
        nonce_context=None,
    )


def test_authenticator_rejects_missing_headers() -> None:
    """Reject unauthenticated A2A requests before protocol dispatch."""
    authenticator = A2ARequestAuthenticator(resource_server=Mock())
    with pytest.raises(ClientAuthenticationError):
        authenticator.authenticate(
            headers={},
            http_method="POST",
            target_uri="https://metro.example.com/a2a",
            expected_issuer="https://nebula.example.com",
        )
