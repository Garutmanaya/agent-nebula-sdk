# Security Policy

## Core principles

- Do not implement custom cryptographic primitives.
- Use explicit algorithm allowlists.
- Reject ambiguous, malformed, private, or symmetric keys where asymmetric keys are required.
- Keep private keys outside the SDK persistence model.
- Treat registration metadata as untrusted input.
- Bind provider tokens to one resource and one sender key.
- Fail closed on missing keys, invalid metadata, unavailable replay protection, or unsupported protocol configuration.
- Never log assertions, private keys, full access tokens, DPoP proofs, or registration credentials.

## Vulnerability classes covered

- assertion replay
- DPoP replay
- token substitution
- cross-resource token replay
- algorithm confusion and downgrade
- `kid` collision and key confusion
- SSRF through `jwks_uri`
- stale JWKS and unsafe rotation
- clock-skew abuse
- registration flooding
- malformed metadata and oversized payloads
- trust-claim escalation

See `docs/security/threat-model.md`.
