# Phase 2 Requirements

## Objective

Add enterprise-grade lifecycle, certificate, and workload-identity capabilities while preserving the Phase 1 OAuth and DPoP profile.

## Required standards and capabilities

1. **RFC 7592 Dynamic Client Registration Management**: read, update, rotate metadata, and delete registrations with registration access tokens and auditable lifecycle rules.
2. **RFC 8705 OAuth mTLS**: mTLS client authentication and certificate-bound access tokens using `cnf.x5t#S256`.
3. **SPIFFE/SPIRE**: workload identities, SVID validation, trust-domain mapping, bundle rotation, and Kubernetes/enterprise adapters.
4. **Certificate lifecycle**: issuance, renewal, overlap, revocation, trust bundles, expiry monitoring, and key separation.
5. **Enterprise registration**: controlled onboarding, approval, publisher association, software statements, and trust classification.
6. **Pluggable sender constraints**: DPoP and mTLS selectable without changing token-service business flow.
7. **Operational adapters**: PostgreSQL repositories, Redis replay/nonce stores, KMS/HSM signing, metrics, and audit.

## Proposed package locations

```text
oauth/rfc7592/
oauth/rfc8705/
tls/
spiffe/
metadata/
ports/
adapters/
```

## Acceptance criteria

- registration metadata can be safely managed and rotated;
- mTLS clients authenticate without shared secrets;
- certificate-bound tokens fail when presented over another client certificate;
- SPIFFE identities map to registered clients and providers;
- certificate and trust-bundle rotation works with overlap;
- DPoP remains fully supported as an alternate sender constraint;
- Phase 1 public APIs remain backward compatible unless a security correction requires a versioned change.
