# SDK Boundary

## SDK owns

- protocol models, parsing, serialization, validation, and error mapping;
- RFC-compliant client and server services;
- key and metadata resolution ports;
- replay-store ports;
- role facades;
- A2A and MCP transport-security adapters;
- reference in-memory adapters for tests only;
- conformance and adversarial test suites.

## SDK does not own

- PostgreSQL or Redis deployment;
- Agent Nebula schema migrations or repositories;
- Agent Nebula trust-score policy;
- provider-local authorization policy;
- FastAPI routes specific to a product;
- Agent Card discovery analysis;
- parking, travel, BI, or healthcare business behavior;
- long-term private-key storage.

## Why the SDK has no database

Protocol modules depend on storage ports. Agent Nebula supplies durable PostgreSQL/Redis adapters; Agent Genesis supplies secure files, HSM/KMS integrations, or distributed replay adapters. This allows protocol behavior to remain unchanged when infrastructure changes.
