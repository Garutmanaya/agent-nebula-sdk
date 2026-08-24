"""Typed models for MCP authorization discovery and protected requests.

Purpose
-------
Represent the transport-security artifacts required by the MCP authorization
specification while leaving JSON-RPC tool semantics to an MCP implementation.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from agent_nebula_sdk.oauth.rfc8414 import AuthorizationServerMetadata
from agent_nebula_sdk.oauth.rfc9728 import ProtectedResourceMetadata


class McpAuthorizationDiscovery(BaseModel):
    """Combine trusted protected-resource and authorization-server metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protected_resource: ProtectedResourceMetadata
    authorization_server: AuthorizationServerMetadata
    challenged_scopes: tuple[str, ...] = ()


class McpHttpRequest(BaseModel):
    """Describe one authenticated MCP-over-HTTP request before execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    body: bytes
    headers: dict[str, str]


class McpHttpResponse(BaseModel):
    """Expose one parsed MCP-over-HTTP JSON response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status_code: int
    headers: dict[str, str]
    payload: dict[str, Any] | list[Any] | None
    raw_body: bytes
