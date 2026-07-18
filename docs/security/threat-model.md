# Threat Model

## Assets

- client and provider private keys;
- Agent Nebula signing keys;
- registered public-key relationships;
- access tokens and DPoP proofs;
- resource identifiers;
- trust claims;
- replay state;
- Agent Cards and protected-resource metadata.

## Trust boundaries

- open Internet to registration endpoint;
- client to Agent Nebula;
- Agent Nebula to external `jwks_uri`;
- Host to provider;
- SDK to product persistence adapters;
- local process to private-key provider.

## Required mitigations

| Threat | Mitigation |
|---|---|
| stolen token | RFC 9449 sender constraint |
| cross-provider replay | RFC 8707 exact resource + exact `aud` |
| assertion replay | atomic RFC 7523 `jti` store |
| DPoP replay | atomic DPoP `jti` store |
| SSRF via JWKS URI | HTTPS-only policy, DNS/IP restrictions, bounded redirects |
| algorithm confusion | explicit per-profile allowlist |
| key confusion | client-bound `kid`, JWK validation, thumbprints |
| stale key | bounded cache, unknown-`kid` refresh, status checks |
| registration flood | rate-limiting adapter and trust-state separation |
| identity in A2A payload | transport-layer authentication only |
