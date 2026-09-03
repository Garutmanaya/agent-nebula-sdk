# OAuth

The OAuth package groups standards and role composition without embedding product persistence or deployment behavior.

## Protocol modules

- `rfc7523` — JWT Profile for OAuth client authentication and authorization grants
- `rfc7591` — Dynamic Client Registration
- `rfc7592` — Dynamic Client Registration Management
- `rfc8414` — Authorization Server Metadata
- `rfc8705` — OAuth 2.0 mutual-TLS certificate-bound access-token validation
- `rfc8707` — Resource Indicators
- `rfc9068` — JWT Access Token Profile
- `rfc9396` — Rich Authorization Requests placeholder
- `rfc9449` — DPoP
- `rfc9728` — Protected Resource Metadata

## OAuth roles

- `client` — composes client-side OAuth protocols
- `authorization_server` — composes Authorization Server protocols
- `resource_server` — composes Resource Server validation protocols

Protocol modules implement standards. Role modules compose standards. Product-specific policy, databases, routes, secrets, and deployment configuration belong outside the SDK.

Agent Nebula-specific security extensions must be additive and must not change standards-compliant OAuth wire behavior.
