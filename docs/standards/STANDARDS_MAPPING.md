# Standards Mapping

| Standard | Purpose | Package | current | Future work |
|---|---|---|---|---|
| RFC 7517 | JWK/JWKS representation | `jose/jwk`, `jose/jwks` | Implemented | Additional key types only when required |
| RFC 7638 | JWK thumbprints | `jose/thumbprint` | Implemented | None planned |
| RFC 7523 | JWT assertions and client authentication | `oauth/rfc7523` | Implemented | Integrate mTLS alternatives in current |
| RFC 7591 | Dynamic registration | `oauth/rfc7591` | Implemented | Standards extensions only as required |
| RFC 8707 | Resource indicators | `oauth/rfc8707` | Implemented | More product-specific resource policies through ports |
| RFC 9068 | JWT access-token profile | `oauth/rfc9068` | Implemented | Certificate binding in current |
| RFC 9449 | DPoP | `oauth/rfc9449` | Implemented | Distributed replay stores in products |
| RFC 8414 | Authorization-server metadata | `oauth/rfc8414` | Implemented | Additional registered metadata extensions as required |
| RFC 9728 | Protected-resource metadata | `oauth/rfc9728` | Implemented | Broader ecosystem interoperability |
| A2A | HTTP authentication metadata and invocation | `a2a` | Implemented security layer | Complete A2A semantics remain external |
| MCP authorization | Client ID Metadata Documents, RFC 9728, RFC 8414/OIDC discovery, and protected calls | `mcp` | Implemented current profile | OAuth draft evolution and product authorization-code UX |
| RFC 7592 | Registration management | `oauth/rfc7592` | Implemented | Product persistence and lifecycle adapters |
| RFC 8705 | OAuth mTLS | `oauth/rfc8705`, `tls` | Not implemented | current |
| SPIFFE/SPIRE | Workload identity | `spiffe` | Not implemented | current |
| RFC 9396 | Rich Authorization Requests | `oauth/rfc9396` | Not implemented | current |
| W3C DID/VC/VP | Decentralized identity | `identity` | Not implemented | current |
| RFC 9635 | GNAP | `gnap` | Not implemented | current |
