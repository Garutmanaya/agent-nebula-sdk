# Phase 3 Requirements

## Objective

Add rich authorization context, decentralized identity, credential presentation, and federation without moving provider business authorization into the registry.

## Required standards and capabilities

1. **RFC 9396 RAR**: structured `authorization_details` models, validators, and provider-local interpretation ports.
2. **W3C DID**: DID document resolution and verification-method selection through pluggable resolvers.
3. **W3C VC/VP and OpenID4VP**: credential and presentation verification, issuer trust, status checking, and selective disclosure profiles.
4. **RFC 9635 GNAP**: independent grant-negotiation module and facade adapter; OAuth remains supported.
5. **Advanced ABAC**: typed security context and policy-decision integration for provider-local rules.
6. **Federation**: signed metadata, trust anchors, multi-registry issuer resolution, and policy boundaries.
7. **Software statements and trust frameworks**: signed onboarding evidence and certification claims.

## Proposed package locations

```text
oauth/rfc9396/
identity/did/
identity/vc/
identity/oid4vp/
gnap/
federation/
policy/
```

## Acceptance criteria

- new authorization detail types can be added without changing token core code;
- credential verification is independent of provider business policy;
- registry-issued identity claims and third-party credentials remain distinguishable;
- GNAP and OAuth can coexist behind separate protocol adapters;
- federation never causes implicit trust expansion;
- Phase 1 and Phase 2 profiles continue to operate unchanged.
