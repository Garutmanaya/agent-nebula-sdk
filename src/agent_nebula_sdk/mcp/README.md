# MCP Authorization Adapters

This package implements the security integration required for protected
MCP-over-HTTP servers.

## Implemented

- RFC 9728 protected-resource discovery
- `WWW-Authenticate` `resource_metadata` handling
- RFC 8414 authorization-server discovery
- advertised authorization-server validation
- DPoP-authenticated MCP HTTP request construction
- protected server challenge and authentication adapters

## Boundaries

The package does not implement MCP JSON-RPC semantics, sessions, tools,
resources, prompts, elicitation, or SSE stream processing. It only secures the
HTTP transport used by those features.
