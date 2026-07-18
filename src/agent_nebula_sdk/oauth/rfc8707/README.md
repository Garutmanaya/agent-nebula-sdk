# RFC 8707 — Resource Indicators for OAuth 2.0

## Purpose

This package lets an OAuth client identify the protected resource where an
access token will be used. The authorization server validates the `resource`
parameter, resolves it to a registered protected resource, and selects the
future token audience. A resource server independently validates that audience.

## Standards

- RFC 8707 Sections 2, 2.1, 2.2, and 3
- RFC 3986 absolute URI syntax
- RFC 7519 `aud` claim integration (implemented fully in Step 6 / RFC 9068)

## Public components

- `ResourceIndicatorValidator`: absolute URI, fragment, query, scheme, duplicate,
  and multiplicity validation.
- `ResourceResolutionService`: maps requested resources to registered audiences.
- `ResourceParameterCodec`: preserves repeated form parameters and JWT
  string-or-array representations.
- `ResourceAudienceValidator`: rejects cross-provider token use.
- `ResourceRegistry`: product-owned persistence port.
- `InMemoryResourceRegistry`: reference adapter for tests and examples.

## Phase 1 profile

RFC 8707 permits multiple resource parameters. Agent Nebula Phase 1 requires
exactly one HTTPS resource per token to minimize multi-audience token risk.
The generic policy can be configured for multiple or abstract resource URIs
where a deployment explicitly requires full RFC flexibility.

## Extension points

- canonical resource aliases and tenant-aware identifiers;
- PostgreSQL resource registry adapter in Agent Nebula;
- prior-grant subset validation for authorization-code and refresh-token grants;
- RFC 9068 token issuer integration;
- RFC 9728 protected-resource metadata.
