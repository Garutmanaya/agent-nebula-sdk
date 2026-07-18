# Step 2 — JOSE Key Foundation

Step 2 implements the shared foundations required by every later authentication and token module.
It intentionally does not implement OAuth client assertions, registration, access-token issuance,
or DPoP yet.

## Implemented standards

- RFC 7517: typed public JWK and JWK Set handling.
- RFC 7518: RSA and EC key parameter interpretation.
- RFC 7638: deterministic JWK thumbprints.
- RFC 8037: Ed25519 OKP public keys and thumbprint members.

## Security profile

- Public registration accepts RSA, EC, and Ed25519 public keys.
- Private and symmetric material is rejected from public JWK payloads.
- RSA keys must be at least 2048 bits.
- EC points are validated against their declared curve.
- Duplicate non-empty `kid` values are rejected.
- Missing `kid` is usable only when selection remains unambiguous.
- Remote `jwks_uri` retrieval requires URI-policy validation, bounded responses, strict JSON,
  cache expiration, and one refresh for an unknown `kid`.
- Open-registration deployments should reject private, loopback, link-local, and otherwise
  non-public JWKS targets unless an explicit enterprise/local policy allows them.

## Public modules

```text
agent_nebula_sdk.jose.jwk
agent_nebula_sdk.jose.jwks
agent_nebula_sdk.jose.thumbprint
agent_nebula_sdk.adapters.httpx_transport
```

## Next implementation step

Step 3 will implement RFC 7523 `private_key_jwt` on top of these public-key and key-resolution APIs.
