# Agent Genesis Integration

The Host consumes the client facade. Each provider consumes the client facade for registration/authentication and the resource-server facade for invocation validation.

## Host responsibilities

- generate and persist RFC 7523 and DPoP key pairs;
- register once and reuse identity across restarts;
- request resource-bound tokens;
- build DPoP proofs for token and provider requests;
- cache tokens only until expiry and audience change.

## Provider responsibilities

- register its OAuth identity and Agent Card separately;
- publish public JWKS and protected-resource metadata;
- validate access token and DPoP proof;
- maintain replay state suitable for deployment topology;
- apply local authorization policy after SDK authentication succeeds.
