# Repository Boundaries

```text
agent-nebula-sdk
  protocol implementation and contracts only

agent-nebula
  registry, authorization-server deployment, trust, persistence, UI

agent-genesis
  host runtime, provider runtime, A2A workflows, business data, UI
```

Agent Nebula implements durable adapters for client registration, resource registration, key metadata, replay protection, and audit. Agent Genesis uses SDK client/resource-server roles and owns private keys, local policies, and business databases.
