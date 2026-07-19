"""HTTP retrieval and caching tests for MCP Client ID Metadata Documents."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.mcp.client_id_metadata import (
    ClientIdMetadataCache,
    ClientIdMetadataPolicy,
    ClientIdMetadataResolver,
)
from agent_nebula_sdk.ports.http import HttpResponse


class FixedClock:
    """Deterministic mutable clock for cache tests."""

    def __init__(self) -> None:
        """Initialize the clock to a stable instant."""
        self.current = datetime(2026, 7, 19, tzinfo=UTC)

    def now(self) -> datetime:
        """Return the configured instant."""
        return self.current


class RecordingTransport:
    """Return configured responses and record requested URLs."""

    def __init__(self, responses: list[HttpResponse]) -> None:
        """Store responses in request order."""
        self.responses = list(responses)
        self.urls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Return the next configured response."""
        self.urls.append(url)
        return self.responses.pop(0)

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResponse:
        """Reject unsupported POST use in this resolver test."""
        raise AssertionError(f"unexpected POST {url}")


def metadata_response(client_id: str, *, cache_control: str = "max-age=300") -> HttpResponse:
    """Build one valid metadata response."""
    body = json.dumps(
        {
            "client_id": client_id,
            "client_name": "Example MCP Client",
            "redirect_uris": ["http://127.0.0.1:3000/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
    ).encode()
    return HttpResponse(
        status_code=200,
        headers={"content-type": "application/json", "cache-control": cache_control},
        body=body,
    )


def test_resolver_fetches_validates_and_caches_document() -> None:
    """Resolve once and reuse a valid cached document."""
    client_id = "https://client.example.com/oauth/client.json"
    clock = FixedClock()
    transport = RecordingTransport([metadata_response(client_id)])
    resolver = ClientIdMetadataResolver(
        transport=transport,
        policy=ClientIdMetadataPolicy(dns_resolver=lambda _hostname: ["93.184.216.34"]),
        cache=ClientIdMetadataCache(clock=clock),
    )

    first = resolver.resolve(client_id)
    second = resolver.resolve(client_id)

    assert first is second
    assert transport.urls == [client_id]
    assert first.cache_max_age_seconds == 300


def test_resolver_rejects_document_identity_mismatch() -> None:
    """Reject metadata fetched from a URL that claims another client identity."""
    requested = "https://client.example.com/oauth/client.json"
    transport = RecordingTransport(
        [metadata_response("https://attacker.example.com/oauth/client.json")]
    )
    resolver = ClientIdMetadataResolver(
        transport=transport,
        policy=ClientIdMetadataPolicy(dns_resolver=lambda _hostname: ["93.184.216.34"]),
    )

    with pytest.raises(ProtocolValidationError) as exc_info:
        resolver.resolve(requested)

    assert exc_info.value.code == "invalid_client_metadata_document"


def test_no_store_response_is_not_cached() -> None:
    """Honor Cache-Control no-store by resolving the document again."""
    client_id = "https://client.example.com/oauth/client.json"
    clock = FixedClock()
    transport = RecordingTransport(
        [metadata_response(client_id, cache_control="no-store"), metadata_response(client_id)]
    )
    resolver = ClientIdMetadataResolver(
        transport=transport,
        policy=ClientIdMetadataPolicy(dns_resolver=lambda _hostname: ["93.184.216.34"]),
        cache=ClientIdMetadataCache(clock=clock),
        default_ttl=timedelta(minutes=5),
    )

    resolver.resolve(client_id)
    resolver.resolve(client_id)

    assert transport.urls == [client_id, client_id]


def test_cache_expires_invalidates_and_evicts_oldest() -> None:
    """Exercise cache expiration, explicit invalidation, and bounded capacity."""
    from agent_nebula_sdk.mcp.client_id_metadata import ClientIdMetadataDocument
    from agent_nebula_sdk.mcp.client_id_metadata.models import ResolvedClientIdMetadata

    clock = FixedClock()
    cache = ClientIdMetadataCache(clock=clock, maximum_entries=1)
    first = ResolvedClientIdMetadata(
        document=ClientIdMetadataDocument(
            client_id="https://one.example.com/oauth/client.json",
            client_name="One",
            redirect_uris=("https://one.example.com/callback",),
        ),
        source_url="https://one.example.com/oauth/client.json",
    )
    second = ResolvedClientIdMetadata(
        document=ClientIdMetadataDocument(
            client_id="https://two.example.com/oauth/client.json",
            client_name="Two",
            redirect_uris=("https://two.example.com/callback",),
        ),
        source_url="https://two.example.com/oauth/client.json",
    )
    cache.put(first, ttl=timedelta(seconds=10))
    cache.put(second, ttl=timedelta(seconds=20))
    assert cache.get(first.source_url) is None
    assert cache.get(second.source_url) is second

    cache.invalidate(second.source_url)
    assert cache.get(second.source_url) is None

    cache.put(first, ttl=timedelta(seconds=1))
    clock.current += timedelta(seconds=2)
    assert cache.get(first.source_url) is None

    with pytest.raises(ValueError):
        cache.put(first, ttl=timedelta(0))
    with pytest.raises(ValueError):
        ClientIdMetadataCache(clock=clock, maximum_entries=0)


def test_resolver_rejects_transport_and_payload_failures() -> None:
    """Fail closed for status, size, content type, JSON, and non-object payloads."""
    from agent_nebula_sdk.core.errors import ExternalServiceError

    client_id = "https://client.example.com/oauth/client.json"
    responses = (
        HttpResponse(404, {"content-type": "application/json"}, b"{}"),
        HttpResponse(200, {"content-type": "application/json"}, b"x" * 20),
        HttpResponse(200, {"content-type": "text/plain"}, b"{}"),
        HttpResponse(200, {"content-type": "application/json"}, b"{"),
        HttpResponse(200, {"content-type": "application/json"}, b"[]"),
    )
    expected_codes = (
        "client_metadata_http_error",
        "client_metadata_response_too_large",
        "client_metadata_content_type_error",
        "client_metadata_json_error",
        "client_metadata_json_error",
    )
    for response, expected_code in zip(responses, expected_codes, strict=True):
        resolver = ClientIdMetadataResolver(
            transport=RecordingTransport([response]),
            policy=ClientIdMetadataPolicy(dns_resolver=lambda _hostname: ["93.184.216.34"]),
            maximum_response_bytes=10,
        )
        with pytest.raises(ExternalServiceError) as exc_info:
            resolver.resolve(client_id)
        assert exc_info.value.code == expected_code


def test_resolver_configuration_and_cache_ttl_bounds() -> None:
    """Validate configuration and cap server-provided cache durations."""
    client_id = "https://client.example.com/oauth/client.json"
    clock = FixedClock()
    transport = RecordingTransport([metadata_response(client_id, cache_control="max-age=999999")])
    cache = ClientIdMetadataCache(clock=clock)
    resolver = ClientIdMetadataResolver(
        transport=transport,
        policy=ClientIdMetadataPolicy(dns_resolver=lambda _hostname: ["93.184.216.34"]),
        cache=cache,
        default_ttl=timedelta(minutes=1),
        maximum_ttl=timedelta(minutes=2),
    )
    resolver.resolve(client_id)
    clock.current += timedelta(minutes=3)
    assert cache.get(client_id) is None

    with pytest.raises(ValueError):
        ClientIdMetadataResolver(
            transport=transport,
            policy=ClientIdMetadataPolicy(),
            default_ttl=timedelta(0),
        )
    with pytest.raises(ValueError):
        ClientIdMetadataResolver(
            transport=transport,
            policy=ClientIdMetadataPolicy(),
            default_ttl=timedelta(minutes=2),
            maximum_ttl=timedelta(minutes=1),
        )
    with pytest.raises(ValueError):
        ClientIdMetadataResolver(
            transport=transport,
            policy=ClientIdMetadataPolicy(),
            maximum_response_bytes=0,
        )


def test_force_refresh_bypasses_valid_cache() -> None:
    """Allow products to refresh changed client metadata explicitly."""
    client_id = "https://client.example.com/oauth/client.json"
    clock = FixedClock()
    transport = RecordingTransport([metadata_response(client_id), metadata_response(client_id)])
    resolver = ClientIdMetadataResolver(
        transport=transport,
        policy=ClientIdMetadataPolicy(dns_resolver=lambda _hostname: ["93.184.216.34"]),
        cache=ClientIdMetadataCache(clock=clock),
    )

    resolver.resolve(client_id)
    resolver.resolve(client_id, force_refresh=True)

    assert transport.urls == [client_id, client_id]
