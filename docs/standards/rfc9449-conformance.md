# RFC 9449 Conformance Matrix

| Requirement | Status | Implementation |
|---|---|---|
| `typ=dpop+jwt` | Implemented | `DpopProofBuilder`, `DpopProofValidator` |
| Asymmetric signature and embedded public `jwk` | Implemented | builder and validator |
| Reject private/symmetric JWK material | Implemented | RFC 7517 public JWK models |
| `jti`, `htm`, `htu`, `iat` | Implemented | `DpopProofClaims` |
| Query/fragment excluded from `htu` | Implemented | `DpopTargetUriNormalizer` |
| Token-endpoint DPoP validation | Implemented | `validate_token_request` |
| `cnf.jkt` access-token binding | Implemented | RFC 9068 integration and binding service |
| `Authorization: DPoP` | Implemented | `DpopHttpHeaderCodec` |
| Protected-resource `ath` validation | Implemented | `AccessTokenHashService` and validator |
| Proof-key match against `cnf.jkt` | Implemented | resource validation |
| Proof replay detection | Implemented through port | `DpopReplayStore` |
| Authorization-server nonce | Implemented through port | `DpopNonceService`, `DpopNonceStore` |
| Resource-server nonce | Implemented through same port | context-scoped nonce validation |
| `use_dpop_nonce` response body mapping | Deferred to HTTP route adapters | Step 8/product integration |
| Refresh-token sender constraint | Core key binding available; grant integration deferred | product token service |
| Distributed replay persistence | Product adapter required | Agent Nebula/provider integration |
