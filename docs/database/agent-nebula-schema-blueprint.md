# Agent Nebula Schema Blueprint

This is a product schema blueprint, not an SDK-owned migration. Agent Nebula must map it to its schema-first database API.

## Core entities

```mermaid
erDiagram
    OAUTH_CLIENT ||--o{ OAUTH_CLIENT_KEY : owns
    OAUTH_CLIENT ||--o{ CLIENT_REGISTRATION_EVENT : has
    OAUTH_CLIENT ||--o{ TOKEN_AUDIT_EVENT : receives
    REGISTERED_RESOURCE ||--o{ TOKEN_AUDIT_EVENT : targeted
    OAUTH_CLIENT ||--o{ REPLAY_IDENTIFIER : submits

    OAUTH_CLIENT {
      uuid oauth_client_id PK
      text client_identifier UK
      text entity_type
      text registration_profile
      text trust_status
      text jwks_uri
      jsonb inline_jwks
      text token_endpoint_auth_method
      timestamptz created_at
      timestamptz updated_at
      timestamptz disabled_at
    }

    OAUTH_CLIENT_KEY {
      uuid oauth_client_key_id PK
      uuid oauth_client_id FK
      text kid
      text kty
      text alg
      text use
      jsonb public_jwk
      text status
      timestamptz valid_from
      timestamptz valid_until
      timestamptz revoked_at
    }

    REGISTERED_RESOURCE {
      uuid resource_id PK
      text resource_uri UK
      uuid agent_id
      text status
      timestamptz created_at
      timestamptz updated_at
    }

    REPLAY_IDENTIFIER {
      uuid replay_identifier_id PK
      text namespace
      text subject
      text jti
      timestamptz expires_at
      timestamptz consumed_at
    }
```

## Schema design rules

- Schema SQL is the source of truth for DB types.
- XML query contracts reference real table columns.
- Domain commands use schema-aligned Python types.
- External strings are converted once at API/application boundaries.
- Repositories perform explicit mapping only.
- JSONB is reserved for protocol metadata whose shape is governed by an RFC model.
- Stable identifiers, statuses, timestamps, and relationships remain relational.

## Future additions without core-table redesign

- RFC 8705 certificate bindings: separate `oauth_client_certificate` table.
- SPIFFE: separate `workload_identity_binding` table.
- DID/VC: separate `decentralized_identity` and `credential_evidence` tables.
- RAR: JSONB authorization-detail audit linked to token event.
- GNAP: separate grant negotiation and continuation tables.
