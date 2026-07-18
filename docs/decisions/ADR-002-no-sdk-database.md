# ADR-002: No SDK-Owned Database

## Decision

The SDK defines persistence ports and reference in-memory adapters but owns no schema or database runtime.

## Rationale

Protocol logic must remain portable across PostgreSQL, Redis, secure files, KMS/HSM, and future infrastructure.
