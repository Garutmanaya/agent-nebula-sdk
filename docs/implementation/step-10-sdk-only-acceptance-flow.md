# Step 10 — SDK-only Host → Registry → Provider acceptance flow

## Purpose

Step 10 proves that the Phase 1 protocol modules compose through their public
role facades without Agent Nebula or Agent Genesis product code.

## Verified sequence

```mermaid
sequenceDiagram
    participant H as Host client
    participant AS as SDK authorization server
    participant P as SDK provider resource server

    H->>AS: RFC 7591 open registration with public JWKS
    AS-->>H: client_id and UNVERIFIED registration state
    P->>AS: RFC 7591 open provider registration with public JWKS
    AS-->>P: provider client_id
    H->>AS: RFC 7523 private_key_jwt + RFC 8707 resource + RFC 9449 proof
    AS->>AS: Validate assertion, DPoP, replay, and resource mapping
    AS-->>H: RFC 9068 access token bound through cnf.jkt
    H->>P: A2A POST with Authorization: DPoP and request proof
    P->>P: Validate issuer, audience, signature, ath, htm, htu, key, and replay
    P->>P: Apply provider-local operation policy
    P-->>H: Authenticated A2A response
```

## Implementation

The reusable harness is exposed as:

```python
from agent_nebula_sdk.conformance import Phase1AcceptanceHarness

result = Phase1AcceptanceHarness().run()
```

The harness uses only SDK public roles plus reference in-memory adapters. The
bridge from RFC 7591 records to RFC 7523 key resolution explicitly represents
the PostgreSQL adapter that Agent Nebula will provide during product
integration.

## Negative acceptance checks

The acceptance suite verifies rejection of:

- a replayed RFC 7523 client assertion;
- a DPoP-bound token used with a different private key;
- a proof used with the wrong HTTP method;
- a replayed protected-resource DPoP proof.

Existing protocol tests also cover wrong audience, wrong URI, incorrect `ath`,
expired assertions and tokens, unknown `kid`, invalid algorithms, malformed
metadata, and registration failures.

## Product boundary

The harness is not a deployable authorization server. It does not own database
schemas, HTTP routes, private-key custody, trust scoring, or provider business
policy. Those remain adapters in Agent Nebula and Agent Genesis.
