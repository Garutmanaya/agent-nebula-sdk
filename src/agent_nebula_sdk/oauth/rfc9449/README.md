# RFC 9449 DPoP

This package implements OAuth 2.0 Demonstrating Proof of Possession for the
client, authorization-server, and protected-resource roles.

## Standards

- RFC 9449 Sections 4–8
- RFC 7638 JWK thumbprints
- RFC 7515 JSON Web Signature
- RFC 7517 JSON Web Key
- RFC 9068 JWT access-token profile integration

## Public components

- `DpopProofBuilder`: creates a fresh request-bound proof JWT.
- `DpopProofValidator`: validates token-endpoint and resource-request proofs.
- `DpopTokenBindingService`: creates and reads `cnf.jkt` token bindings.
- `AccessTokenHashService`: computes the mandatory resource-request `ath`.
- `DpopNonceService`: issues optional server nonces.
- `DpopReplayStore` and `DpopNonceStore`: product-owned persistence ports.

## Security processing order

1. Enforce proof size and `typ=dpop+jwt`.
2. Enforce the explicit asymmetric algorithm allowlist.
3. Parse and validate the embedded public JWK.
4. Verify the proof signature.
5. Match `htm` and normalized `htu` to the HTTP request.
6. Enforce the proof age window and optional server nonce.
7. Validate `ath` for protected-resource requests.
8. Match the JWK thumbprint to access-token `cnf.jkt`.
9. Atomically consume the proof `jti` to reject replay.

## Boundaries

The SDK does not own private-key storage, HTTP routing, access-token storage,
Redis/PostgreSQL schemas, or provider-local authorization policy. Products
implement persistence ports and use the role facades introduced in Step 8.
