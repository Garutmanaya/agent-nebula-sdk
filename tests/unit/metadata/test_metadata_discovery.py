"""Unit tests for RFC 8414 and RFC 9728 metadata discovery."""

from __future__ import annotations

import json

import pytest

from agent_nebula_sdk.core.errors import ExternalServiceError, ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8414 import (
    AuthorizationServerMetadataClient,
    authorization_server_metadata_url,
)
from agent_nebula_sdk.oauth.rfc9728 import (
    ProtectedResourceMetadataClient,
    protected_resource_metadata_urls,
)
from agent_nebula_sdk.ports.http import HttpResponse


class StaticTransport:
    """Return configured HTTP responses by URL for deterministic discovery tests."""

    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        """Store response fixtures keyed by exact URL."""
        self.responses = responses
        self.requested_urls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Return the configured response or a synthetic 404."""
        self.requested_urls.append(url)
        return self.responses.get(
            url,
            HttpResponse(status_code=404, headers={"content-type": "application/json"}, body=b"{}"),
        )

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResponse:
        """Reject POST because metadata discovery only performs GET requests."""
        raise AssertionError("POST is not expected")


def json_response(payload: dict[str, object]) -> HttpResponse:
    """Create a successful JSON metadata response."""
    return HttpResponse(
        status_code=200,
        headers={"content-type": "application/json; charset=utf-8"},
        body=json.dumps(payload).encode(),
    )


def test_authorization_server_url_inserts_well_known_before_path() -> None:
    """Construct the RFC 8414 URL correctly for tenant issuers."""
    assert authorization_server_metadata_url("https://auth.example/tenant") == (
        "https://auth.example/.well-known/oauth-authorization-server/tenant"
    )


def test_resource_urls_return_path_specific_then_root() -> None:
    """Return MCP-compatible RFC 9728 discovery candidates in priority order."""
    assert protected_resource_metadata_urls("https://mcp.example/public/mcp") == (
        "https://mcp.example/.well-known/oauth-protected-resource/public/mcp",
        "https://mcp.example/.well-known/oauth-protected-resource",
    )


def test_resource_client_falls_back_from_path_metadata_to_root() -> None:
    """Use root RFC 9728 metadata after a path-specific 404 response."""
    resource = "https://mcp.example/public/mcp"
    _, root = protected_resource_metadata_urls(resource)
    transport = StaticTransport(
        {
            root: json_response(
                {
                    "resource": resource,
                    "authorization_servers": ["https://nebula.example.com"],
                    "dpop_signing_alg_values_supported": ["ES256"],
                    "dpop_bound_access_tokens_required": True,
                }
            )
        }
    )
    metadata = ProtectedResourceMetadataClient(transport=transport).fetch(resource)
    assert metadata.resource == resource
    assert transport.requested_urls[-1] == root


def test_authorization_server_client_rejects_wrong_issuer_in_metadata() -> None:
    """Reject an RFC 8414 authorization-server impersonation response."""
    issuer = "https://nebula.example.com"
    url = authorization_server_metadata_url(issuer)
    transport = StaticTransport(
        {
            url: json_response(
                {
                    "issuer": "https://attacker.example.com",
                    "response_types_supported": [],
                }
            )
        }
    )
    with pytest.raises(ProtocolValidationError) as exc_info:
        AuthorizationServerMetadataClient(transport=transport).fetch(issuer)
    assert exc_info.value.code == "issuer_metadata_mismatch"


def test_authorization_server_client_rejects_non_json_content_type() -> None:
    """Reject RFC 8414 metadata delivered with an unexpected media type."""
    issuer = "https://nebula.example.com"
    url = authorization_server_metadata_url(issuer)
    transport = StaticTransport(
        {url: HttpResponse(status_code=200, headers={"content-type": "text/html"}, body=b"{}")}
    )
    with pytest.raises(ExternalServiceError) as exc_info:
        AuthorizationServerMetadataClient(transport=transport).fetch(issuer)
    assert exc_info.value.code == "metadata_content_type_error"


def test_authorization_server_client_rejects_oversized_metadata() -> None:
    """Apply the configured RFC 8414 response-size boundary before JSON parsing."""
    issuer = "https://nebula.example.com"
    url = authorization_server_metadata_url(issuer)
    transport = StaticTransport(
        {
            url: HttpResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=b"{" + b" " * 100 + b"}",
            )
        }
    )
    with pytest.raises(ExternalServiceError) as exc_info:
        AuthorizationServerMetadataClient(
            transport=transport,
            maximum_response_bytes=16,
        ).fetch(issuer)
    assert exc_info.value.code == "metadata_response_too_large"


def test_authorization_server_client_rejects_non_object_json() -> None:
    """Reject arrays because RFC 8414 metadata responses must be JSON objects."""
    issuer = "https://nebula.example.com"
    url = authorization_server_metadata_url(issuer)
    transport = StaticTransport(
        {
            url: HttpResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=b"[]",
            )
        }
    )
    with pytest.raises(ExternalServiceError) as exc_info:
        AuthorizationServerMetadataClient(transport=transport).fetch(issuer)
    assert exc_info.value.code == "metadata_json_error"


def test_invalid_issuer_and_resource_urls_are_rejected() -> None:
    """Reject insecure or ambiguous RFC 8414/RFC 9728 discovery identifiers."""
    with pytest.raises(ProtocolValidationError):
        authorization_server_metadata_url("http://auth.example.com")
    with pytest.raises(ProtocolValidationError):
        protected_resource_metadata_urls("https://mcp.example.com/mcp#fragment")
