# Current MCP Authorization Profile

## Supported client identification

The SDK supports the current MCP priority model without implementing an MCP
RFC 7591 fallback:

1. product-managed pre-registration;
2. OAuth Client ID Metadata Documents;
3. no Dynamic Client Registration path inside the MCP package.

RFC 7591 remains available in `oauth/rfc7591` for A2A and general OAuth
onboarding.

## Client ID Metadata Documents

Implemented requirements include:

- the `client_id` is an HTTPS URL;
- a non-root path component is required;
- user information, fragments, and dot path segments are rejected;
- document `client_id` must match the fetched URL using exact string
  comparison;
- `client_id`, `client_name`, and `redirect_uris` are required;
- HTTPS redirects and policy-approved loopback HTTP redirects are supported;
- `private_key_jwt` requires `jwks_uri` or inline `jwks`;
- DNS and network-range policy limits SSRF exposure;
- valid JSON responses are size-bounded;
- redirects are not followed by the SDK resolver;
- only valid documents are cached;
- `Cache-Control: no-store` disables caching.

## Authorization-server discovery

MCP discovery uses RFC 9728 protected-resource metadata and then tries
authorization-server metadata in this order:

1. RFC 8414 path insertion;
2. OpenID Connect path insertion;
3. OpenID Connect path appending for issuers with a path component.

The returned issuer must match exactly.

## Resource targeting

The shared RFC 8707 implementation remains the source of truth for the
`resource` parameter and exact protected-resource audience validation.

## Deferred MCP work

The SDK does not implement JSON-RPC methods, sessions, tools, prompts,
resources, elicitation, OAuth authorization-code UI, or PKCE state storage.
Those are product or MCP framework responsibilities.
