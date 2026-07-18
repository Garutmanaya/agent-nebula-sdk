# Type and Conversion Policy

## Bottom-up truth flow

```text
PostgreSQL schema
→ XML query contract
→ generated typed DB request/result model
→ repository mapping
→ domain command
→ application/API boundary conversion
```

Conversions occur only at external boundaries. Internal layers preserve canonical types.

Examples:

- JWT `jti` string → `UUID` at claim boundary when schema type is UUID.
- ISO timestamp string → timezone-aware `datetime` at HTTP boundary.
- JWK JSON → validated `PublicJwk` model at registration boundary.
- JSONB adaptation is performed only by the DB executor based on the query's schema-backed column type.

No field-name type guessing, generic string fallback, broad dictionaries, or lower-layer coercion is permitted.
