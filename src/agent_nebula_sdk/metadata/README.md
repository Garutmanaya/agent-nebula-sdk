# OAuth Metadata

This package implements the metadata and discovery primitives required by the
SDK's A2A and MCP adapters.

## Standards

- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- RFC 6750 — `WWW-Authenticate` challenge parameters
- RFC 9449 — DPoP metadata and challenge usage

## Public API

- `AuthorizationServerMetadata`
- `ProtectedResourceMetadata`
- `OAuthMetadataClient`
- `OAuthChallengeCodec`
- well-known URL construction helpers

## Boundaries

The package validates metadata but does not own DNS policy, HTTP routing,
metadata persistence, signed-metadata trust anchors, or OpenID Connect
Discovery. Those are adapters or future extensions.
