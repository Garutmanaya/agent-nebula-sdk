# Agent Nebula SDK Roadmap

## Current status

Phase 1 is complete. The SDK now provides an independently verified Host → Authorization Server → Provider flow with no dependency on Agent Nebula or Agent Genesis application code.

| Step | Scope | Status |
|---|---|---|
| Step 1 | Architecture, module boundaries, plugin model, persistence ports | Complete |
| Step 2 | RFC 7517 JWK/JWKS and RFC 7638 thumbprints | Complete |
| Step 3 | RFC 7523 `private_key_jwt` and JWT bearer assertions | Complete |
| Step 3.1 | Documentation and source-quality baseline | Complete |
| Step 4 | RFC 7591 Dynamic Client Registration | Complete |
| Step 5 | RFC 8707 Resource Indicators | Complete |
| Step 6 | RFC 9068 JWT Access Token Profile | Complete |
| Step 7 | RFC 9449 DPoP | Complete |
| Step 8 | Client, authorization-server, and resource-server facades | Complete |
| Step 9 | A2A and MCP security adapters | Complete |
| Step 10 | SDK-only Phase 1 acceptance flow | Complete |
| Documentation Freeze | Phase 1 release and future-phase documentation | Complete |
| Runtime/MCP Update | Protocol Runtime and current MCP Client ID Metadata profile | Complete |

## Standards mapping

| Standard | Purpose | SDK package | Phase | Status |
|---|---|---|---|---|
| RFC 7517 | JSON Web Key and JWK Set | `jose/jwk`, `jose/jwks` | 1 | Implemented |
| RFC 7638 | Deterministic JWK thumbprints | `jose/thumbprint` | 1 | Implemented |
| RFC 7523 | JWT assertions and `private_key_jwt` | `oauth/rfc7523` | 1 | Implemented |
| RFC 7591 | Dynamic Client Registration | `oauth/rfc7591` | 1 | Implemented |
| RFC 8707 | Resource Indicators and audience selection | `oauth/rfc8707` | 1 | Implemented |
| RFC 9068 | JWT Profile for OAuth 2.0 Access Tokens | `oauth/rfc9068` | 1 | Implemented |
| RFC 9449 | DPoP sender-constrained tokens | `oauth/rfc9449` | 1 | Implemented |
| RFC 8414 | Authorization Server Metadata | `metadata` | 1 | Implemented |
| RFC 9728 | Protected Resource Metadata | `metadata` | 1 | Implemented |
| A2A | Agent Card security and authenticated HTTP invocation | `a2a` | 1 | Implemented |
| MCP authorization | Client ID Metadata Documents, OAuth/OIDC discovery, protected invocation | `mcp` | 1 | Implemented |
| RFC 7592 | Dynamic Client Registration Management | `oauth/rfc7592` | 2 | Planned |
| RFC 8705 | OAuth mTLS and certificate-bound tokens | `oauth/rfc8705`, `tls` | 2 | Planned |
| SPIFFE/SPIRE | Workload identity and SVID lifecycle | `spiffe` | 2 | Planned |
| RFC 9396 | Rich Authorization Requests | `oauth/rfc9396` | 3 | Planned |
| W3C DID/VC/VP | Decentralized identity and credentials | `identity` | 3 | Planned |
| OpenID4VP | Verifiable presentation transport | `identity` | 3 | Planned |
| RFC 9635 | GNAP grant negotiation | `gnap` | 3 | Planned |

## Fixed dependency order

```text
JWK/JWKS
→ private_key_jwt
→ dynamic registration
→ resource indicators
→ JWT access tokens
→ DPoP
→ role facades
→ A2A/MCP adapters
→ protocol runtime
→ SDK-only acceptance
→ product adapters
```

## Next product work

1. Integrate Agent Nebula with PostgreSQL and Redis adapters.
2. Replace Agent Nebula's embedded custom OAuth implementation with SDK authorization-server facades.
3. Integrate Agent Genesis Host with the client facade.
4. Integrate Agent Genesis provider agents with client and resource-server facades.
5. Run the real UI → Host → Nebula → Provider acceptance flow.

## Phase 2

Phase 2 adds enterprise lifecycle and workload-identity capabilities without replacing Phase 1:

- RFC 7592 registration management;
- RFC 8705 mTLS client authentication;
- certificate-bound access tokens;
- SPIFFE/SPIRE workload identity;
- certificate issuance, rotation, revocation, and trust bundles;
- controlled registration and enterprise approval workflows;
- stronger trust and registration classification.

See `docs/phase2/PHASE2_REQUIREMENTS.md`.

## Phase 3

Phase 3 adds richer decentralized authorization and federation:

- RFC 9396 Rich Authorization Requests;
- provider-local ABAC integration;
- W3C DID, VC, and VP;
- OpenID4VP;
- RFC 9635 GNAP;
- software statements and federation metadata;
- multi-registry trust and policy negotiation.

See `docs/phase3/PHASE3_REQUIREMENTS.md`.
