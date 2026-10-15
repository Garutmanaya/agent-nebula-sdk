# Security Policy

## Security model

Agent Nebula SDK separates identity, token issuance, sender constraint, and provider-local authorization.

- The authorization server authenticates clients and issues signed claims.
- RFC 8707 binds a token to an intended protected resource.
- RFC 9449 binds the token to a client-held DPoP key.
- The provider validates the token and proof, then applies local policy.
- The SDK never receives or persists product private keys unless a consuming product explicitly supplies a key adapter.

## Security controls

- asymmetric client authentication through RFC 7523;
- public key registration through RFC 7591 and RFC 7517;
- exact issuer and audience validation;
- short-lived JWT access tokens following RFC 9068;
- DPoP method, URI, token-hash, key-binding, nonce, and replay validation;
- algorithm allowlists and `alg=none` rejection;
- JWKS retrieval controls, bounded responses, cache expiry, and key rotation;
- metadata issuer/resource identity validation;
- stable protocol errors that do not leak cryptographic internals.

## Product responsibilities

Consuming products must provide:

- secure private-key custody;
- durable registration and key repositories;
- atomic replay storage suitable for their deployment topology;
- TLS configuration and certificate validation;
- audit retention and privacy controls;
- provider-local authorization policies;
- rate limiting, abuse prevention, and operational monitoring.

## Known current boundaries

- mTLS and certificate-bound tokens are deferred to current.
- SPIFFE/SPIRE workload identity is deferred to current.
- RAR, DID/VC, GNAP, and federation are deferred to current.
- Reference in-memory adapters are not production persistence.
- The SDK does not make business-level authorization decisions.

## Reporting vulnerabilities

Report suspected vulnerabilities privately to the repository maintainers. Include the affected version, reproduction steps, expected impact, and whether the issue involves token replay, key confusion, metadata impersonation, or validation bypass.
