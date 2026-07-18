# Step 1 Deliverable Manifest

This deliverable contains architecture and design only. It intentionally contains no Python protocol implementation.

- Architecture and repository boundaries
- Public role APIs
- Class and dependency diagrams
- Plugin and extension model
- Configuration model
- Storage ports and Agent Nebula schema blueprint
- Bottom-up database type policy
- Phase 1 standards profile
- Phase 2 and Phase 3 protocol map
- Open registration, private-key JWT, resource token, DPoP, key rotation, and end-to-end flows
- Threat model and key lifecycle
- Testing strategy and acceptance gates
- ADRs for major decisions
- Normative source list


## Step 3 source additions

- `src/agent_nebula_sdk/oauth/rfc7523/`
- `tests/unit/oauth/rfc7523/`
- `tests/integration/oauth/`
- `docs/implementation/step-3-rfc7523-private-key-jwt.md`
- `docs/standards/rfc7523-conformance.md`
