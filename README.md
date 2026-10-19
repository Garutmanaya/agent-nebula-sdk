# Agent Nebula SDK

**Agent Nebula SDK** is a Python security library that provides reusable OAuth, JOSE, token-validation, and sender-constrained authentication components for agent applications. It supplies security primitives and integration contracts; it does **not** operate the hosted Agent Nebula Registry, OAuth server, or policy service.

The SDK is used by [Agent Nebula Platform](https://github.com/garutmanaya/agent-nebula-platform), which integrates these capabilities with the official A2A Python SDK. Developers building agents can use [SecureAgent](https://github.com/garutmanaya/agent-nebula-secureagent) as the higher-level interface.

## Why use the SDK?

- **Standards-based security:** reusable OAuth and JOSE implementations instead of application-specific token and proof validation.
- **Separation of responsibilities:** client, authorization-server, and resource-server facades with application-supplied persistence and policy decisions.
- **Sender-constrained requests:** DPoP proof validation, token binding, replay checks, and resource targeting.
- **Protocol integration:** HTTP security components for A2A and MCP authorization profiles; the SDK does not implement A2A or MCP message transport.
- **Composable infrastructure:** ports and adapters for storage, key management, and HTTP interactions.

## Security capabilities

| Capability | Standard or interface |
| --- | --- |
| JWK, JWKS, key thumbprints | RFC 7517, RFC 7638 |
| JWT client authentication | RFC 7523 |
| Dynamic client registration and management | RFC 7591, RFC 7592 |
| Authorization-server and protected-resource metadata | RFC 8414, RFC 9728 |
| Resource indicators | RFC 8707 |
| JWT access tokens | RFC 9068 |
| Demonstrating proof of possession | RFC 9449 (DPoP) |
| A2A and MCP security | HTTP authentication/authorization integration |

For implementation details, constraints, and conformance references, see [standards mapping](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/docs/standards/STANDARDS_MAPPING.md), [security model](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/docs/security/threat-model.md), and [documentation index](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/docs/INDEX.md). Additional protocol modules in the source tree should not be assumed to constitute a complete hosted service.

## Install

Requires Python 3.12.

```bash
pip install agent-nebula-sdk
```

To develop from source:

```bash
uv sync --group dev
make verify
```

## Architecture and integrations

The SDK implements security primitives and exposes contracts for application-owned persistence, credential storage, and authorization decisions. [Architecture](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/docs/architecture/sdk-overview.md) · [Public API](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/docs/architecture/public-api.md) · [Ports and adapters](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/docs/architecture/ports-and-adapters.md) · [Agent Nebula integration](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/docs/integration/agent-nebula.md).

## Documentation

Start with the [documentation index](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/docs/INDEX.md). It links to architecture, API facades, OAuth standards, authentication flows, configuration, testing, and integration guidance.

## License

Apache License 2.0. See [LICENSE](https://github.com/garutmanaya/agent-nebula-sdk/blob/main/LICENSE).
