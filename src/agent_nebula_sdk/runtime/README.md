# Protocol Runtime

The runtime is the SDK composition root. It groups configured client,
authorization-server, and resource-server facades and exposes a namespaced
component registry for additive extensions.

It does **not** move RFC modules under a new `protocols/` hierarchy and does
not instantiate databases, transports, key stores, or global state. Product
applications construct those dependencies explicitly and inject completed
facades or plugins.

Standard names:

- `oauth.client`
- `oauth.authorization_server`
- `oauth.resource_server`
- `mcp.client_id_metadata`
- future names such as `oauth.rfc8705`, `identity.spiffe`, or `gnap.server`
