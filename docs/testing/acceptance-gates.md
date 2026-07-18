# Acceptance Gates

## Architecture gate

- module and dependency rules approved;
- storage contracts approved;
- standards profile approved;
- threat model approved.

## Module gate

A module must pass formatting, linting, strict typing, tests, coverage, conformance mapping, documentation, and manual review before the next module starts.

## Phase 1 SDK gate

The SDK-only test must complete:

```text
open RFC 7591 registration
→ RFC 7523 authentication
→ RFC 8707 target selection
→ RFC 9449 token-request proof
→ RFC 9068 DPoP-bound token
→ direct A2A provider invocation
→ provider token/DPoP validation
→ local policy result
```

Negative cases include wrong audience/key/method/URI/`ath`, expiration, assertion replay, DPoP replay, unknown `kid`, revoked key, and algorithm downgrade.
