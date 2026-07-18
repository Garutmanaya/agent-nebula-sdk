# Agent Nebula SDK — Step 1 Architecture Baseline

This repository is the frozen architecture and design baseline for a reusable security and protocol SDK consumed by **Agent Nebula** and **Agent Genesis**.

Step 1 intentionally contains no protocol implementation. It defines the public contracts, module boundaries, storage ports, extension model, standards profile, diagrams, testing strategy, and acceptance gates that implementation must follow.

## Primary goals

1. Every protocol is an independent, replaceable module.
2. Products compose modules through interfaces and factories, never internal imports.
3. The SDK owns protocol behavior but owns no product database or business policy.
4. Agent Nebula and Agent Genesis remain independently deployable.
5. Phase 2 and Phase 3 standards can be added without modifying stable Phase 1 modules.
6. Every security-sensitive API is traceable to a standard, test, and failure contract.

## Phase 1 standards profile

- RFC 7517 — JSON Web Key (JWK)
- RFC 7638 — JWK Thumbprint
- RFC 7523 — JWT Profiles for OAuth 2.0 Client Authentication
- RFC 7591 — OAuth 2.0 Dynamic Client Registration
- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- RFC 8707 — Resource Indicators for OAuth 2.0
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
- RFC 9449 — Demonstrating Proof of Possession (DPoP)
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- A2A protocol security integration at the HTTP layer
- MCP authorization integration through OAuth metadata

## Repository map

```text
agent-nebula-sdk-step1/
├── contracts/                 # Stable public port and model specifications
├── diagrams/                  # Consolidated Mermaid diagrams
├── docs/
│   ├── architecture/
│   ├── configuration/
│   ├── database/
│   ├── decisions/
│   ├── flows/
│   ├── roadmap/
│   ├── security/
│   ├── standards/
│   └── testing/
├── scripts/                   # Documentation validation only
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── SECURITY.md
└── ROADMAP.md
```

## Required review order

1. `ARCHITECTURE.md`
2. `docs/architecture/sdk-boundary.md`
3. `docs/architecture/module-and-plugin-model.md`
4. `docs/database/storage-contracts.md`
5. `docs/database/agent-nebula-schema-blueprint.md`
6. `docs/standards/phase-1-profile.md`
7. `docs/testing/acceptance-gates.md`

## Hard rule

Implementation may add code inside a module, but it may not bypass, merge, or reverse the dependencies defined in this baseline without a new Architecture Decision Record (ADR).
