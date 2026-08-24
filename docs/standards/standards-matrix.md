# Standards Matrix

| Standard | Purpose | Phase | SDK module | Product adapter |
|---|---|---:|---|---|
| RFC 7517 | JWK/JWKS | 1 | `jwks` | key persistence / HTTP hosting |
| RFC 7638 | JWK thumbprint | 1 | `jwks.thumbprint` | none |
| RFC 7523 | private_key_jwt | 1 | `oauth.client_assertion` | client/key registry |
| RFC 7591 | dynamic registration | 1 | `oauth.registration` | registration persistence/policy |
| RFC 8414 | AS metadata | 1 | `metadata.authorization_server` | endpoint composition |
| RFC 8707 | resource indicators | 1 | `oauth.resource_indicator` | resource registry |
| RFC 9068 | JWT access tokens | 1 | `oauth.access_token` | signing key provider |
| RFC 9449 | DPoP | 1 | `dpop` | replay store |
| RFC 9728 | resource metadata | 1 | `metadata.protected_resource` | endpoint composition |
| RFC 7592 | registration management | Implemented | `oauth/rfc7592` | registration lifecycle |
| RFC 8705 | mTLS OAuth | Phase 2 | `future.mtls` | PKI/certificate store |
| SPIFFE/SPIRE | workload identity | Phase 2 | `future.spiffe` | Workload API |
| W3C DID/VC/VP | decentralized trust | Phase 3 | `future.decentralized_identity` | credential verifier |
| RFC 9396 | RAR | Phase 3 | `future.rar` | policy handlers |
| RFC 9635 | GNAP | Phase 3 | `future.gnap` | grant persistence |
| RFC 9421 | HTTP Message Signatures | Candidate | `future.http_signatures` | key resolver |
| A2A v1 security | agent transport | 1+ | `a2a` | Agent Card/HTTP server |
| MCP authorization | MCP transport | 1+ | `mcp` | MCP server/client |
