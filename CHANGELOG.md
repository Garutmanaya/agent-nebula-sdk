# Changelog

## 1.12.0 — OAuth Standards Normalization

- Moved RFC 8414 Authorization Server Metadata into `oauth/rfc8414`.
- Moved RFC 9728 Protected Resource Metadata into `oauth/rfc9728`.
- Implemented RFC 7592 Dynamic Client Registration Management with read, update, delete, registration access-token rotation, and pluggable persistence/lifecycle ports.
- Grouped OAuth client, Authorization Server, and Resource Server role facades under `oauth/`.
- Retained compatibility re-exports for the previous top-level metadata and role package paths.
- Extended the transport port with PUT and DELETE operations required by RFC 7592.
- Added direct RFC 8414, RFC 9728, and RFC 7592 tests.

## 1.11.0

- Added pluggable top-level onboarding orchestration.
- Added open, API-key, initial-access-token, software-statement, and explicit mTLS-placeholder authenticators.
- Added Agent, RFC 7591 OAuth-client, and RFC 9728 protected-resource profiles.
- Added atomic product transaction and audit ports plus ProtocolRuntime integration.
## 1.10.0 — Protocol Runtime and Current MCP Profile

- Added `ProtocolRuntime` as the explicit composition root for client, authorization-server, and resource-server facades.
- Added a namespaced, duplicate-safe component registry and additive plugin contract.
- Added OAuth Client ID Metadata Document models, validation, SSRF policy, retrieval, caching, and runtime plugin support for MCP.
- Updated MCP authorization-server discovery to try RFC 8414 and OpenID Connect metadata endpoints in the current MCP-required order.
- Added `client_id_metadata_document_supported` and PKCE metadata fields to authorization-server metadata.
- Kept RFC 7591 available for A2A and general OAuth while removing any MCP dependency on DCR.
- Added unit and architecture tests for runtime composition and the current MCP profile.

## Phase 1 Documentation Freeze

Documentation-only release based on the completed Step 10 codebase.

- Updated top-level project, roadmap, security, and contributor documentation.
- Added a documentation index and normalized architecture documentation.
- Added Phase 1 completion and release reports.
- Added standards mapping and per-standard implementation summaries.
- Added integration guides for Agent Nebula and Agent Genesis.
- Added persistence and database-adapter guidance.
- Added Phase 2 and Phase 3 requirements and extension maps.
- No Python source, tests, package structure, or public APIs changed.

## 1.9.0 — Phase 1 SDK Acceptance

- Added SDK-only Host → Authorization Server → Provider conformance harness.
- Added negative tests for assertion replay, DPoP replay, wrong key, and wrong HTTP method.
- Completed RFC 7517, 7638, 7523, 7591, 8707, 9068, 9449, 8414, and 9728 Phase 1 profile.
- Completed A2A and MCP HTTP security adapters.
