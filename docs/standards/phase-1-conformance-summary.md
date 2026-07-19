# Phase 1 conformance summary

| Standard | Acceptance evidence |
|---|---|
| RFC 7517 | Host, provider, DPoP, and issuer public JWKs are parsed and validated |
| RFC 7638 | DPoP key thumbprint is bound into and checked from `cnf.jkt` |
| RFC 7523 | Host authenticates with a short-lived, replay-protected `private_key_jwt` |
| RFC 7591 | Host and provider use open dynamic registration with inline public JWKS |
| RFC 8707 | Host requests one provider resource and receives one exact audience |
| RFC 9068 | Authorization server issues a signed `at+jwt` access token |
| RFC 9449 | Token and A2A requests are sender-constrained and replay protected |
| A2A security | Credentials remain in HTTP headers and local provider policy decides the operation |

The SDK implements the selected Agent Nebula Phase 1 profile. It does not claim
that every optional deployment feature in every referenced RFC is enabled by
default; each protocol conformance document records supported and deferred
features.
