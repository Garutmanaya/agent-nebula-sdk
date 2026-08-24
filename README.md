# Agent Nebula SDK

Agent Nebula SDK is a reusable, persistence-neutral security and protocol library shared by Agent Nebula, Agent Genesis, and future agent products. Phase 1 is complete and provides standards-based client onboarding, asymmetric authentication, provider-targeted access tokens, sender-constrained invocation, a shared Protocol Runtime, and HTTP security adapters for A2A and the current MCP authorization profile.


## Secure onboarding

`agent_nebula_sdk.onboarding` is the top-level composition API for authenticated Agent, OAuth client, and RFC 9728 protected-resource registration. It reuses the existing RFC modules and delegates atomic persistence to application-provided ports.

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
| RFC 7592 | Dynamic Client Registration Management | Implemented |
| RFC 8707 | Resource Indicators | Implemented |
| RFC 9068 | JWT access-token profile | Implemented |
| RFC 9449 | DPoP | Implemented |
| RFC 8414 | Authorization-server metadata | Implemented |
| RFC 9728 | Protected-resource metadata | Implemented |
| A2A security integration | HTTP-layer authentication and Agent Card metadata | Implemented |
| MCP authorization integration | Client ID Metadata Documents, OAuth/OIDC discovery, and protected invocation | Implemented |

See `docs/standards/STANDARDS_MAPPING.md` and `docs/phase1/PHASE1_COMPLETION_REPORT.md`.

## Repository structure

```text
src/agent_nebula_sdk/
├── jose/                  # JWK, JWKS, thumbprints
├── oauth/                 # OAuth RFC modules and role composition
│   ├── rfc7523/           # JWT assertions / private_key_jwt
│   ├── rfc7591/           # Dynamic Client Registration
│   ├── rfc7592/           # Registration Management
│   ├── rfc8414/           # Authorization Server Metadata
│   ├── rfc8707/           # Resource Indicators
│   ├── rfc9068/           # JWT Access Token Profile
│   ├── rfc9449/           # DPoP
│   ├── rfc9728/           # Protected Resource Metadata
│   ├── client/            # OAuth client role composition
│   ├── authorization_server/ # Authorization Server role composition
│   └── resource_server/   # Resource Server role composition
├── a2a/                   # A2A HTTP security adapters
├── mcp/                   # Current MCP OAuth security profile
├── runtime/               # Protocol composition root and plugin registry
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

New standards must be added through independent modules, ports, adapters, runtime plugins, and facade composition. Stable Phase 1 modules must not be modified merely to add Phase 2 or Phase 3 capabilities unless a standards correction or security defect requires it and is recorded in an ADR.
