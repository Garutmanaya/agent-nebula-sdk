# RFC 9068 — JWT Access Token Profile

This package implements authorization-server issuance and resource-server
validation of OAuth 2.0 access tokens encoded as JWTs.

## Standards

- RFC 9068 Sections 2–5
- RFC 7519 JSON Web Token
- RFC 7515 JSON Web Signature
- RFC 8725 JWT Best Current Practices
- RFC 8707 Resource Indicators
- RFC 6750 Bearer Token error semantics

## Public components

- `JwtAccessTokenIssuer`: creates signed `at+jwt` tokens.
- `JwtAccessTokenValidator`: validates signature, issuer, audience, time, type,
  required claims, and algorithm policy.
- `Rfc9068Policy`: immutable deployment profile.
- `AccessTokenVerificationKeyResolver`: product-owned key-resolution port.

## Boundaries

The package does not own signing-key storage, JWKS publication, resource
registration, HTTP routes, provider policy, or access-token revocation. RFC
8707 supplies the audience. RFC 9449 integration supplies the optional `cnf.jkt` confirmation claim and
sender-constrained request validation without changing this package's core
issuer and validator roles.
