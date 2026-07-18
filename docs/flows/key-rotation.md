# Key Rotation

```mermaid
stateDiagram-v2
    [*] --> ActiveOld
    ActiveOld --> Overlap: publish new key
    Overlap --> ActiveNew: begin signing with new kid
    ActiveNew --> RetiringOld: wait for assertion/token lifetime
    RetiringOld --> RetiredOld: remove old key from active use
    RetiredOld --> RevokedOld: security event if required
```

Rotation requirements:

- stable client identity across restart;
- unique `kid` per client;
- both keys available during overlap;
- unknown `kid` triggers one bounded JWKS refresh;
- old key removed only after all dependent artifacts expire;
- revocation is distinct from normal retirement.
