# RFC 7591 Dynamic Client Registration

This package implements the SDK's OAuth 2.0 Dynamic Client Registration profile.

## Responsibilities

- Parse and validate standard RFC 7591 client metadata.
- Support `jwks_uri` and inline `jwks` with mutual exclusion.
- Support open and initial-access-token-controlled onboarding policies.
- Process verified software statements through an injected verifier.
- Preserve product-specific extension metadata for policy validation.
- Generate and persist client records through product-owned ports.
- Provide a transport-neutral registration client.

## Product boundaries

The package does not own a database, trust-score algorithm, publisher model, or HTTP framework routes. Agent Nebula supplies persistence and policy adapters. Agent Genesis uses the client-side facade.

## Standards

- RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol
- RFC 6749 — OAuth 2.0 client and redirect URI rules
- RFC 7517 — JWK and JWK Set metadata
- RFC 7523 — `private_key_jwt` authentication used after registration
- RFC 7592 — reserved for a future registration-management plugin
