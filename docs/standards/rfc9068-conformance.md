# RFC 9068 Conformance Matrix

| Requirement | Status |
|---|---|
| Signed JWT access tokens | Implemented |
| `none` prohibited | Implemented |
| RS256 support | Implemented and mandatory in policy |
| `typ` equal to `at+jwt` or `application/at+jwt` | Implemented |
| Required `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id` | Implemented |
| Optional `auth_time`, `acr`, `amr` | Implemented |
| `scope`, `groups`, `roles`, `entitlements` | Implemented |
| RFC 8707 audience input | Implemented through issuer request |
| Exact issuer and audience validation | Implemented |
| Asymmetric signature verification | Implemented |
| Explicit algorithm allowlist | Implemented |
| Clock-skew allowance | Implemented |
| RFC 6750 `invalid_token` mapping | Stable SDK error implemented |
| Encrypted JWT access tokens | Deferred; not required by RFC 9068 baseline |
| RFC 8414 metadata publication | Reserved for metadata milestone |
| Sender constraint / `cnf` | implementation RFC 9449 |
