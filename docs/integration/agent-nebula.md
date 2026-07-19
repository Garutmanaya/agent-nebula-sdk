# Agent Nebula Integration

Agent Nebula consumes the authorization-server facade and supplies product adapters.

## Required adapters

- registered-client repository and key resolver;
- dynamic-registration persistence;
- protected-resource registry and audience mapping;
- token signing-key provider and JWKS publisher;
- assertion and DPoP replay stores;
- nonce store;
- trust-claim provider;
- audit event sink;
- HTTP route/error mapping.

## Migration flow

1. Add schema and adapters without replacing current endpoints.
2. Run SDK conformance against Agent Nebula adapters.
3. expose RFC 7591 registration and the standard token endpoint;
4. migrate providers and Host clients to `private_key_jwt` and DPoP;
5. retain old endpoints only as explicitly marked compatibility facades;
6. remove centralized agent-capability scopes from token issuance.
