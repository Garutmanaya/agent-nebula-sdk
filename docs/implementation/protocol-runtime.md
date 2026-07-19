# Protocol Runtime

## Purpose

`ProtocolRuntime` is the single SDK composition boundary used by Agent Nebula,
Agent Genesis Host, and Provider Agents. It groups configured role facades and
optional protocol plugins without moving RFC modules under a generic
`protocols/` hierarchy.

## Standard roles

The runtime reserves these component names:

```text
oauth.client
oauth.authorization_server
oauth.resource_server
```

Applications may configure one, two, or all roles. Requesting an unconfigured
role fails with a stable `ConfigurationError`.

## Plugins

A plugin implements `ProtocolRuntimePlugin` and registers one or more services
under namespaced identifiers. Example:

```text
mcp.client_id_metadata
oauth.rfc8705
identity.spiffe
gnap.server
```

Duplicate registration is rejected. This prevents a later plugin from
silently replacing a security-sensitive component.

## Boundary

The runtime does not create:

- PostgreSQL or Redis clients;
- HTTP transports;
- signing keys or HSM clients;
- replay stores;
- product configuration;
- HTTP routes;
- provider authorization policy.

Products construct those collaborators explicitly and inject completed
facades or plugins. This preserves dependency inversion and keeps the SDK
persistence-neutral.
