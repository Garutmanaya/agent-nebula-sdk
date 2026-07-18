# Agent Nebula SDK Roadmap

## Current status

| Step | Scope | Status |
|---|---|---|
| Step 1 | Architecture, boundaries, plugin model, DB ports, and documentation plan | Complete |
| Step 2 | RFC 7517 JWK/JWKS and RFC 7638 thumbprints | Complete |
| Step 3 | RFC 7523 `private_key_jwt` and JWT bearer assertions | Complete |
| Step 3.1 | Documentation, comments, package READMEs, and quality gates | Complete |
| Step 4 | RFC 7591 Dynamic Client Registration | Complete |
| Step 5 | RFC 8707 Resource Indicators | Complete |
| Step 6 | RFC 9068 JWT Access Token Profile | Next |
| Step 7 | RFC 9449 DPoP | Pending |
| Step 8 | Client, authorization-server, and resource-server role facades | Pending |
| Step 9 | A2A and MCP security adapters | Pending |
| Step 10 | SDK-only Host → Registry → Provider acceptance flow | Pending |

## Standards mapping

| Standard | Purpose | SDK package | Phase | Status |
|---|---|---|---|---|
| RFC 7517 | JSON Web Key and JWK Set representation | `jose/jwk`, `jose/jwks` | 1 | Implemented |
| RFC 7638 | Deterministic JWK thumbprints | `jose/thumbprint` | 1 | Implemented |
| RFC 7523 | JWT assertions and `private_key_jwt` | `oauth/rfc7523` | 1 | Implemented |
| RFC 7591 | Dynamic Client Registration | `oauth/rfc7591` | 1 | Implemented |
| RFC 8707 | Resource Indicators and audience selection | `oauth/rfc8707` | 1 | Implemented |
| RFC 9068 | JWT Profile for OAuth 2.0 Access Tokens | `oauth/rfc9068` | 1 | Next |
| RFC 9449 | DPoP sender-constrained tokens | `oauth/rfc9449` | 1 | Pending |
| RFC 8414 | Authorization Server Metadata | `metadata` | 1 | Pending |
| RFC 9728 | Protected Resource Metadata | `metadata` | 1 | Pending |
| A2A | Agent Card security and authenticated HTTP invocation | `a2a` | 1 | Pending |
| MCP authorization | OAuth discovery and protected MCP invocation | `mcp` | 1 | Pending |
| RFC 7592 | Registration management | `oauth/rfc7592` | 2 | Package reserved |
| RFC 8705 | OAuth mTLS and certificate-bound tokens | `oauth/rfc8705`, `tls` | 2 | Package reserved |
| SPIFFE/SPIRE | Workload identity | `spiffe` | 2 | Package reserved |
| RFC 9396 | Rich Authorization Requests | `oauth/rfc9396` | 3 | Package reserved |
| W3C DID/VC/VP | Decentralized identity and credentials | `identity` | 3 | Package reserved |
| RFC 9635 | GNAP grant negotiation | `gnap` | 3 | Package reserved |

## Fixed dependency order

```text
JWK/JWKS
→ private_key_jwt
→ dynamic registration
→ resource indicators
→ JWT access-token profile
→ DPoP
→ role facades
→ A2A/MCP adapters
→ SDK-only end-to-end conformance
```

## Product integration after SDK conformance

1. Update Agent Nebula with PostgreSQL/Redis adapters.
2. Update Agent Genesis Host with the client role.
3. Update Agent Genesis providers with client and resource-server roles.
