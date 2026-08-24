"""DPoP-authenticated MCP-over-HTTP client security adapter.

The adapter prepares and sends JSON messages. It does not implement MCP session
state, tool discovery, elicitation, or JSON-RPC method semantics.
"""

from __future__ import annotations

import json
from typing import Any

from agent_nebula_sdk.core.errors import ExternalServiceError
from agent_nebula_sdk.mcp.models import McpHttpRequest, McpHttpResponse
from agent_nebula_sdk.oauth.client import OAuthClientFacade
from agent_nebula_sdk.oauth.rfc9449 import DpopSigningKey
from agent_nebula_sdk.ports.http import HttpTransport


class McpHttpSecurityClient:
    """Send DPoP-authenticated JSON requests to an MCP HTTP endpoint."""

    def __init__(self, *, oauth: OAuthClientFacade, transport: HttpTransport) -> None:
        """Inject the OAuth client role and HTTP transport."""
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
        protocol_version: str | None = None,
        session_id: str | None = None,
    ) -> McpHttpRequest:
        """Serialize an MCP message and attach OAuth/DPoP transport headers."""
        artifacts = self._oauth.build_protected_request(
            http_method="POST",
            target_uri=endpoint,
            access_token=access_token,
            dpop_key=dpop_key,
            nonce=nonce,
        )
        headers = {
            **artifacts.headers,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if protocol_version is not None:
            headers["MCP-Protocol-Version"] = protocol_version
        if session_id is not None:
            headers["Mcp-Session-Id"] = session_id
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return McpHttpRequest(endpoint=endpoint, body=body, headers=headers)

    def send(self, request: McpHttpRequest) -> McpHttpResponse:
        """Execute one prepared MCP request and parse a JSON response when present."""
        response = self._transport.post(
            request.endpoint,
            headers=request.headers,
            body=request.body,
        )
        payload: dict[str, Any] | list[Any] | None = None
        content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
        if response.body and content_type == "application/json":
            try:
                parsed = json.loads(response.body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ExternalServiceError(
                    "MCP server returned invalid JSON",
                    code="invalid_mcp_response",
                    details={"status_code": response.status_code},
                ) from exc
            if not isinstance(parsed, (dict, list)):
                raise ExternalServiceError(
                    "MCP response must be a JSON object or array",
                    code="invalid_mcp_response",
                )
            payload = parsed
        return McpHttpResponse(
            status_code=response.status_code,
            headers=response.headers,
            payload=payload,
            raw_body=response.body,
        )
