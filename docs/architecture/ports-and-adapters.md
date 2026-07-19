# Ports and Adapters

Ports define the persistence and infrastructure behavior required by protocol services. Examples include client repositories, key resolvers, resource registries, replay stores, clocks, nonce stores, signing keys, and HTTP transports.

Reference in-memory adapters exist for tests and local examples. Production products should provide PostgreSQL, Redis, HSM/KMS, filesystem, or service-specific implementations without changing protocol code.
