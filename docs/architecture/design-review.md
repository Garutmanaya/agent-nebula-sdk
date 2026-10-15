# Design Review Conclusion

The design has been reviewed against the project's primary constraints: modularity, plugin-based extension, product independence, schema-first persistence, standards traceability, and end-to-end testability.

## Decisions considered stable

1. Separate SDK repository with independent semantic versioning.
2. Role facades for client, authorization server, and resource server.
3. Protocol modules depend only on domain models and ports.
4. No SDK-owned database.
5. Agent Nebula owns durable persistence and trust policy.
6. Agent Genesis owns private keys, local policy, and business data.
7. Schema-first Agent Nebula DB adapters with one conversion boundary.
8. Open registration and controlled registration are policy plugins over the same RFC 7591 engine.
9. Provider-local business authorization; no central capability permission catalog.
10. Future standards are additive modules selected by configuration.

## Main future-risk controls

- Stable interfaces prevent current identity mechanisms from modifying current authentication services.
- Separate tables/adapters prevent future protocol evidence from overloading core OAuth records.
- Versioned storage contracts detect incompatible Agent Nebula schema changes.
- Plugin startup validation prevents partially implemented standards from becoming active.
- Conformance matrices prevent minimal sketches from being labeled complete implementations.
