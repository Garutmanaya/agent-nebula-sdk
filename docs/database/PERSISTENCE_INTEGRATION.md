# Persistence Integration

The SDK has no database. Products implement storage ports and own schemas, migrations, transactions, retention, and operational scaling.

Agent Nebula typically persists registrations, public keys, resources, aliases, token audit, replay identifiers, nonces, trust state, and signing-key metadata. Agent Genesis persists private-key references, registration identifiers, token caches, provider replay state, and business data.

Every adapter must accept and return SDK typed models; database-specific conversion occurs only at the adapter boundary.
