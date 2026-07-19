# Package Architecture

Top-level packages are organized by functional category rather than a generic protocol registry.

```text
jose/                  JWK, JWKS, thumbprints
oauth/                 OAuth RFC modules
metadata/              Authorization and protected-resource metadata
client/                Client role composition
authorization_server/  Authorization-server composition
resource_server/       Protected-resource composition
a2a/                   A2A HTTP security integration
mcp/                   MCP OAuth security integration
ports/                  Infrastructure contracts
adapters/               Reference adapters
conformance/            Cross-role acceptance harness
```

Future packages remain category based: `tls`, `spiffe`, `identity`, and `gnap`.
