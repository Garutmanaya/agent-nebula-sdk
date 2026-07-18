# Step 8 — Role facades

Step 8 composes the Phase 1 RFC modules into three stable product-facing roles:

- `OAuthClientFacade` for Host and Provider OAuth-client behavior;
- `AuthorizationServerFacade` for Agent Nebula registration and token issuance;
- `ResourceServerFacade` for Provider token and DPoP validation.

The facades are deliberately thin. They preserve RFC-specific request and result models, accept all infrastructure as injected collaborators, and contain no database, HTTP route, trust-score, or provider business-policy implementation.

```mermaid
flowchart LR
    C[Client facade] --> A[RFC 7523]
    C --> R[RFC 8707]
    C --> D[RFC 9449]
    AS[Authorization-server facade] --> A
    AS --> R
    AS --> T[RFC 9068]
    AS --> D
    RS[Resource-server facade] --> T
    RS --> R
    RS --> D
```
