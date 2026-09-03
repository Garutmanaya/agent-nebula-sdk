# MCP Authorization Adapters

This package implements the security integration required for protected
MCP-over-HTTP servers using the current MCP authorization profile.

## Implemented

- OAuth Client ID Metadata Documents for URL-based client identification
- RFC 9728 protected-resource discovery
- `WWW-Authenticate` `resource_metadata` handling
- RFC 8414 authorization-server discovery
- OpenID Connect discovery fallback in MCP-required priority order
- exact issuer and protected-resource validation
- RFC 8707 resource targeting through the shared OAuth client facade
- DPoP-authenticated MCP HTTP request construction
- protected server challenge and authentication adapters

## Registration boundary

The MCP package does not use RFC 7591 Dynamic Client Registration. RFC 7591
remains available under `oauth/rfc7591` for general OAuth clients.
Pre-registered MCP clients remain a deployment option outside this package.

## Boundaries

The package does not implement MCP JSON-RPC semantics, sessions, tools,
resources, prompts, elicitation, or SSE stream processing. It secures the HTTP
transport used by those features.
