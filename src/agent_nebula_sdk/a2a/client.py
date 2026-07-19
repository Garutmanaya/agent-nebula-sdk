"""Authenticated HTTP client adapter for A2A requests.

The adapter handles transport-level JSON and DPoP headers only. It does not
implement A2A task semantics, streaming, push notifications, or business
payload construction.
"""

from __future__ import annotations

import json
from typing import Any

from agent_nebula_sdk.a2a.models import A2AHttpRequest, A2AHttpResponse
from agent_nebula_sdk.client import OAuthClientFacade
from agent_nebula_sdk.core.errors import ExternalServiceError
from agent_nebula_sdk.oauth.rfc9449 import DpopSigningKey
from agent_nebula_sdk.ports.http import HttpTransport


class A2AHttpSecurityClient:
    """Send DPoP-authenticated JSON requests to an A2A HTTP endpoint."""

    def __init__(self, *, oauth: OAuthClientFacade, transport: HttpTransport) -> None:
        """Inject the shared OAuth client facade and HTTP transport."""
        self._oauth = oauth
        self._transport = transport

    def build_request(
        self,
        *,
        endpoint: str,
        access_token: str,
        dpop_key: DpopSigningKey,
        payload: dict[str, Any] | list[Any],
        nonce: str | None = None,
    ) -> A2AHttpRequest:
        """Serialize an A2A JSON payload and attach request-specific DPoP headers."""
        artifacts = self._oauth.build_protected_request(
            http_method="POST",
            target_uri=endpoint,
            access_token=access_token,
            dpop_key=dpop_key,
            nonce=nonce,
        )
        headers = {
            **artifacts.headers,
            "Content-Type": "application/a2a+json",
            "Accept": "application/a2a+json, application/json",
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return A2AHttpRequest(endpoint=endpoint, body=body, headers=headers)

    def send(self, request: A2AHttpRequest) -> A2AHttpResponse:
        """Execute one prepared request and parse an optional JSON response."""
        response = self._transport.post(
            request.endpoint,
            headers=request.headers,
            body=request.body,
        )
        payload: dict[str, Any] | list[Any] | None = None
        if response.body:
            try:
                parsed = json.loads(response.body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ExternalServiceError(
                    "A2A server returned invalid JSON",
                    code="invalid_a2a_response",
                    details={"status_code": response.status_code},
                ) from exc
            if not isinstance(parsed, (dict, list)):
                raise ExternalServiceError(
                    "A2A response must be a JSON object or array",
                    code="invalid_a2a_response",
                )
            payload = parsed
        return A2AHttpResponse(
            status_code=response.status_code,
            headers=response.headers,
            payload=payload,
            raw_body=response.body,
        )
