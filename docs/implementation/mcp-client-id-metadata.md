# MCP Client ID Metadata Implementation

## Source packages

```text
src/agent_nebula_sdk/mcp/client_id_metadata/
├── models.py
├── policy.py
├── resolver.py
├── cache.py
└── plugin.py
```

## Processing order

```text
client_id URL
→ syntactic URL validation
→ host allowlist policy
→ DNS resolution and network-range checks
→ bounded HTTPS GET through injected transport
→ status/content-type/size validation
→ strict metadata model validation
→ exact client_id/document URL match
→ redirect and authentication policy
→ bounded valid-document cache
```

Errors and malformed documents are never cached.

## Product integration

Agent Nebula should configure the resolver with:

- an HTTP transport that disables redirects;
- TLS verification;
- production DNS/network egress restrictions;
- a durable or bounded in-memory cache adapter;
- an optional trusted-domain allowlist;
- explicit policy for public clients versus `private_key_jwt` clients.

The resolver can be installed in `ProtocolRuntime` through
`McpClientIdMetadataPlugin` and resolved as `mcp.client_id_metadata`.
