# Standards Mapping

| Standard | Purpose | Package | Phase 1 status | Future work |
|---|---|---|---|---|
| RFC 7517 | JWK/JWKS representation | `jose/jwk`, `jose/jwks` | Implemented | Additional key types only when required |
| RFC 7638 | JWK thumbprints | `jose/thumbprint` | Implemented | None planned |
| RFC 7523 | JWT assertions and client authentication | `oauth/rfc7523` | Implemented | Integrate mTLS alternatives in Phase 2 |
| RFC 7591 | Dynamic registration | `oauth/rfc7591` | Implemented | RFC 7592 management in Phase 2 |
| RFC 8707 | Resource indicators | `oauth/rfc8707` | Implemented | More product-specific resource policies through ports |
| RFC 9068 | JWT access-token profile | `oauth/rfc9068` | Implemented | Certificate binding in Phase 2 |
| RFC 9449 | DPoP | `oauth/rfc9449` | Implemented | Distributed replay stores in products |
| RFC 8414 | Authorization-server metadata | `metadata` | Implemented | Additional advertised auth methods |
| RFC 9728 | Protected-resource metadata | `metadata` | Implemented | Broader ecosystem interoperability |
| A2A | HTTP authentication metadata and invocation | `a2a` | Implemented security layer | Complete A2A semantics remain external |
| MCP authorization | OAuth discovery and protected calls | `mcp` | Implemented security layer | OIDC fallback and evolving MCP profiles |
| RFC 7592 | Registration management | `oauth/rfc7592` | Not implemented | Phase 2 |
| RFC 8705 | OAuth mTLS | `oauth/rfc8705`, `tls` | Not implemented | Phase 2 |
| SPIFFE/SPIRE | Workload identity | `spiffe` | Not implemented | Phase 2 |
| RFC 9396 | Rich Authorization Requests | `oauth/rfc9396` | Not implemented | Phase 3 |
| W3C DID/VC/VP | Decentralized identity | `identity` | Not implemented | Phase 3 |
| RFC 9635 | GNAP | `gnap` | Not implemented | Phase 3 |
