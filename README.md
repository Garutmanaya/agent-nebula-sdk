# Agent Nebula SDK

Agent Nebula SDK is a reusable, persistence-neutral security and protocol library shared by Agent Nebula, Agent Genesis, and future agent products. Phase 1 is complete and provides standards-based client onboarding, asymmetric authentication, provider-targeted access tokens, sender-constrained invocation, and HTTP security adapters for A2A and MCP.

## Phase 1 status

Phase 1 implements and verifies the complete SDK-only flow:

```text
Host
→ RFC 7591 open registration
→ RFC 7523 private_key_jwt authentication
→ RFC 8707 resource selection
→ RFC 9068 JWT access token
→ RFC 9449 DPoP sender constraint
→ A2A or MCP protected-resource invocation
→ provider-local authorization
```

The SDK owns protocol models, validation, token construction, role facades, metadata, and extension ports. It does not own product databases, trust-score business rules, HTTP route composition, private-key custody, or provider business policy.

## Implemented standards

| Standard | Purpose | Status |
|---|---|---|
| RFC 7517 | JWK and JWKS | Implemented |
| RFC 7638 | JWK thumbprints | Implemented |
| RFC 7523 | JWT assertions and `private_key_jwt` | Implemented |
| RFC 7591 | Dynamic Client Registration | Implemented |
| RFC 8707 | Resource Indicators | Implemented |
| RFC 9068 | JWT access-token profile | Implemented |
| RFC 9449 | DPoP | Implemented |
| RFC 8414 | Authorization-server metadata | Implemented |
| RFC 9728 | Protected-resource metadata | Implemented |
| A2A security integration | HTTP-layer authentication and Agent Card metadata | Implemented |
| MCP authorization integration | OAuth discovery and protected invocation | Implemented |

See `docs/standards/STANDARDS_MAPPING.md` and `docs/phase1/PHASE1_COMPLETION_REPORT.md`.

## Repository structure

```text
src/agent_nebula_sdk/
├── jose/                  # JWK, JWKS, thumbprints
├── oauth/                 # RFC 7523, 7591, 8707, 9068, 9449
├── metadata/              # RFC 8414 and RFC 9728
├── client/                # Client role facade
├── authorization_server/  # Authorization-server role facade
├── resource_server/       # Resource-server role facade
├── a2a/                   # A2A HTTP security adapters
├── mcp/                   # MCP OAuth security adapters
├── conformance/           # SDK-only Phase 1 harness
├── ports/                 # Persistence and infrastructure contracts
└── adapters/              # Reference adapters
```

## Installation and verification

```bash
uv lock --default-index https://pypi.org/simple
uv sync --group dev
make verify
```

Run only the Phase 1 acceptance scenario:

```bash
uv run python scripts/run_phase1_acceptance.py
```

## Documentation

Start with `docs/INDEX.md`. The most important documents are:

1. `docs/architecture/sdk-overview.md`
2. `docs/standards/STANDARDS_MAPPING.md`
3. `docs/phase1/PHASE1_COMPLETION_REPORT.md`
4. `docs/integration/agent-nebula.md`
5. `docs/integration/agent-genesis.md`
6. `docs/phase2/PHASE2_REQUIREMENTS.md`
7. `docs/phase3/PHASE3_REQUIREMENTS.md`

## Extension rule

New standards must be added through independent modules, ports, adapters, and facade composition. Stable Phase 1 modules must not be modified merely to add Phase 2 or Phase 3 capabilities unless a standards correction or security defect requires it and is recorded in an ADR.
