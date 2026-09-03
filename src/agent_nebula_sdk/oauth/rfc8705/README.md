# RFC 8705

This package implements the resource-server certificate-binding check for OAuth 2.0 mutual-TLS certificate-bound access tokens.

`CertificateBoundAccessTokenValidator` computes the SHA-256 thumbprint of the authenticated TLS client certificate and compares it with the access token `cnf["x5t#S256"]` value. TLS certificate-chain authentication itself is provided by `agent_nebula_sdk.security.MtlsClientCertificateAuthenticator` so it can also be reused independently of OAuth.

Token issuance and TLS listener configuration remain product-owned concerns.
