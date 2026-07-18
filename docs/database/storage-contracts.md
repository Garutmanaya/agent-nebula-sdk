# Storage Contracts

The SDK has no database. It defines transaction-neutral ports with typed domain models.

## Required Agent Nebula ports

```text
ClientRegistrationStore
ClientKeyMetadataStore
ResourceRegistrationStore
ClientAssertionReplayStore
DpopReplayStore
AuthorizationAuditStore
TrustClaimProvider
```

## Required Agent Genesis ports

```text
PrivateKeyProvider
RegistrationStateStore
TokenCache
DpopReplayStore         # provider role
LocalPolicyDecisionPoint
```

## Atomicity requirements

- Consuming a replay identifier must be atomic.
- Client registration and initial key records must commit together.
- Key status transitions must prevent two unrelated keys sharing one active `kid` for a client.
- Token audit failure must not silently weaken token validation; product policy decides whether issuance fails closed.

## Replay-store contract

```text
consume(namespace, subject, jti, expires_at) -> consumed | replay
```

The implementation must guarantee that concurrent calls for the same tuple cannot both succeed.
