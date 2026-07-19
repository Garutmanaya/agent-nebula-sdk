"""Validation tests for MCP OAuth Client ID Metadata Documents."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.mcp.client_id_metadata import (
    ClientIdMetadataDocument,
    ClientIdMetadataPolicy,
    validate_client_identifier_url,
)


def public_dns(_hostname: str) -> list[str]:
    """Return one documentation-only public IP address."""
    return ["93.184.216.34"]


def test_client_identifier_requires_https_path_and_exact_form() -> None:
    """Accept a valid HTTPS metadata URL and reject a root-only URL."""
    valid = "https://client.example.com/oauth/client.json"
    assert validate_client_identifier_url(valid) == valid

    with pytest.raises(ValueError):
        validate_client_identifier_url("https://client.example.com/")


def test_document_requires_key_source_for_private_key_jwt() -> None:
    """Require public key metadata when private_key_jwt is advertised."""
    with pytest.raises(ValueError):
        ClientIdMetadataDocument(
            client_id="https://client.example.com/oauth/client.json",
            client_name="Example MCP Client",
            redirect_uris=("https://client.example.com/callback",),
            token_endpoint_auth_method="private_key_jwt",
        )


def test_policy_accepts_https_and_loopback_redirects() -> None:
    """Allow secure web redirects and native loopback redirects."""
    policy = ClientIdMetadataPolicy(dns_resolver=public_dns)
    client_id = "https://client.example.com/oauth/client.json"
    policy.validate_client_id(client_id)
    policy.validate_document(
        ClientIdMetadataDocument(
            client_id=client_id,
            client_name="Example MCP Client",
            redirect_uris=(
                "https://client.example.com/callback",
                "http://127.0.0.1:32123/callback",
            ),
        )
    )


def test_policy_rejects_private_metadata_address() -> None:
    """Reject SSRF targets that resolve to non-public addresses by default."""
    policy = ClientIdMetadataPolicy(dns_resolver=lambda _hostname: ["127.0.0.1"])

    with pytest.raises(ProtocolValidationError) as exc_info:
        policy.validate_client_id("https://client.example.com/oauth/client.json")

    assert exc_info.value.code == "unsafe_client_metadata_address"


def test_client_identifier_rejects_unsafe_url_components() -> None:
    """Reject user information, dot segments, queries, fragments, and HTTP."""
    invalid_values = (
        "http://client.example.com/oauth/client.json",
        "https://user@client.example.com/oauth/client.json",
        "https://client.example.com/oauth/../client.json",
        "https://client.example.com/oauth/client.json?tenant=1",
        "https://client.example.com/oauth/client.json#fragment",
    )
    for value in invalid_values:
        with pytest.raises(ValueError):
            validate_client_identifier_url(value)

    query_value = "https://client.example.com/oauth/client.json?tenant=1"
    assert validate_client_identifier_url(query_value, allow_query=True) == query_value


def test_document_accepts_private_key_jwt_with_jwks_uri_and_extensions() -> None:
    """Accept public-key authentication and preserve unknown metadata members."""
    document = ClientIdMetadataDocument.model_validate(
        {
            "client_id": "https://client.example.com/oauth/client.json",
            "client_name": "Example MCP Client",
            "redirect_uris": ["https://client.example.com/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://client.example.com/oauth/jwks.json",
            "custom_trust_hint": "partner",
        }
    )

    assert document.extension_metadata() == {"custom_trust_hint": "partner"}


def test_document_rejects_key_source_and_flow_conflicts(rsa_public_jwk: dict[str, str]) -> None:
    """Reject simultaneous key sources and inconsistent OAuth flow metadata."""
    with pytest.raises(ValueError):
        ClientIdMetadataDocument(
            client_id="https://client.example.com/oauth/client.json",
            client_name="Example MCP Client",
            redirect_uris=("https://client.example.com/callback",),
            token_endpoint_auth_method="private_key_jwt",
            jwks_uri="https://client.example.com/jwks.json",
            jwks={"keys": [rsa_public_jwk]},
        )

    with pytest.raises(ValueError):
        ClientIdMetadataDocument(
            client_id="https://client.example.com/oauth/client.json",
            client_name="Example MCP Client",
            redirect_uris=("https://client.example.com/callback",),
            grant_types=("authorization_code",),
            response_types=("token",),
        )


def test_policy_enforces_hosts_dns_and_authentication_method() -> None:
    """Apply host allowlists, DNS failures, and private-key requirements."""
    client_id = "https://client.example.com/oauth/client.json"
    with pytest.raises(ProtocolValidationError) as host_error:
        ClientIdMetadataPolicy(
            allowed_client_hosts=frozenset({"trusted.example.com"}),
            dns_resolver=public_dns,
        ).validate_client_id(client_id)
    assert host_error.value.code == "client_metadata_host_not_allowed"

    with pytest.raises(ProtocolValidationError) as dns_error:
        ClientIdMetadataPolicy(dns_resolver=lambda _hostname: []).validate_client_id(client_id)
    assert dns_error.value.code == "client_metadata_dns_failure"

    document = ClientIdMetadataDocument(
        client_id=client_id,
        client_name="Example MCP Client",
        redirect_uris=("https://client.example.com/callback",),
    )
    with pytest.raises(ProtocolValidationError) as auth_error:
        ClientIdMetadataPolicy(
            require_private_key_jwt=True,
            dns_resolver=public_dns,
        ).validate_document(document)
    assert auth_error.value.code == "client_authentication_method_not_allowed"


def test_policy_rejects_fragment_and_insecure_redirects() -> None:
    """Reject redirect fragments and non-loopback HTTP endpoints."""
    policy = ClientIdMetadataPolicy(dns_resolver=public_dns)
    base = {
        "client_id": "https://client.example.com/oauth/client.json",
        "client_name": "Example MCP Client",
    }
    for redirect_uri in (
        "https://client.example.com/callback#fragment",
        "http://client.example.com/callback",
    ):
        document = ClientIdMetadataDocument(
            **base,
            redirect_uris=(redirect_uri,),
        )
        with pytest.raises(ProtocolValidationError) as exc_info:
            policy.validate_document(document)
        assert exc_info.value.code == "invalid_client_redirect_uri"


def test_policy_wraps_dns_resolver_errors() -> None:
    """Convert operating-system DNS failures into stable protocol errors."""
    def failing_dns(_hostname: str) -> list[str]:
        """Simulate one resolver failure."""
        raise OSError("DNS unavailable")

    policy = ClientIdMetadataPolicy(dns_resolver=failing_dns)
    with pytest.raises(ProtocolValidationError) as exc_info:
        policy.validate_client_id("https://client.example.com/oauth/client.json")
    assert exc_info.value.code == "client_metadata_dns_failure"
