# Testing Strategy

## Test layers

- unit: individual models, codecs, validators, and policy-free services;
- conformance: normative requirement mapping and RFC examples;
- integration: client, authorization server, and resource server composed with in-memory ports;
- external HTTP: all outbound operations mocked;
- adversarial: tampering, replay, downgrade, key confusion, SSRF controls;
- compatibility: rotation overlap and SDK-version interoperability;
- performance: validation latency and replay-store contention.

## External call matrix

Every external operation must test:

- success;
- connection error;
- timeout;
- TLS validation error;
- non-JSON response;
- malformed JSON;
- 4xx;
- 5xx;
- oversized response;
- unsupported content type;
- retry limits;
- cache behavior.

Operations include registration HTTP, token HTTP, JWKS retrieval, protected-resource metadata, authorization-server metadata, A2A invocation, MCP invocation, and future SPIFFE/VC calls.
