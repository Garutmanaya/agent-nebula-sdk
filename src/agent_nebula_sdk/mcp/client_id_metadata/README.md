# MCP Client ID Metadata Documents

This package implements URL-based OAuth client identification for the current
MCP authorization profile. The MCP path does not invoke RFC 7591 Dynamic Client
Registration.

Implemented controls:

- HTTPS Client Identifier URL with a required non-root path;
- no user information, fragments, or dot path segments;
- exact string match between requested URL and document `client_id`;
- required `client_id`, `client_name`, and `redirect_uris`;
- HTTPS or policy-approved loopback redirect URIs;
- optional `private_key_jwt` with `jwks_uri` or inline `jwks`;
- SSRF-aware DNS and network-range policy;
- bounded JSON responses;
- no redirect following in the SDK resolver;
- bounded caching of valid documents only;
- protocol-runtime plugin registration.

RFC 7591 remains available under `oauth/rfc7591` for A2A and general OAuth
registration but is not used by this MCP package.
