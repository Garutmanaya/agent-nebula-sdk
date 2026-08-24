# Package Architecture

Top-level packages are organized by functional category rather than a generic protocol registry.

```text
jose/                  JWK, JWKS, thumbprints
oauth/                 OAuth RFC modules and OAuth role composition
  rfc8414/             Authorization Server Metadata
  rfc9728/             Protected Resource Metadata
  client/              OAuth client composition
  authorization_server/ Authorization Server composition
  resource_server/     Resource Server composition
a2a/                   A2A HTTP security integration
mcp/                   MCP OAuth security integration
ports/                  Infrastructure contracts
adapters/               Reference adapters
conformance/            Cross-role acceptance harness
```

Future packages remain category based: `tls`, `spiffe`, `identity`, and `gnap`.
