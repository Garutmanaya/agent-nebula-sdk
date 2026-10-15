# Future Protocol Map

## current

```text
future/mtls/                  RFC 8705
future/spiffe/                SPIFFE ID, X.509-SVID, JWT-SVID
future/spire/                 Workload API adapter
oauth/rfc7592/                  RFC 7592 — implemented
```

## current

```text
future/rar/                   RFC 9396
future/gnap/                  RFC 9635
future/did/                   W3C DID Core
future/verifiable_credentials/ W3C VC Data Model
future/oid4vp/                OpenID for Verifiable Presentations
future/software_statements/   signed onboarding assertions
future/signed_agent_cards/    A2A signed Agent Card integration
future/http_signatures/       RFC 9421 candidate adapter
```

Each future module must implement an existing stable interface or introduce a new additive interface through an ADR. Placeholders must identify required configuration, ports, models, and test locations.
