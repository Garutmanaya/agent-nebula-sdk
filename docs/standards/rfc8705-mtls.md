# RFC 8705 OAuth mTLS

Add an `MtlsClientAuthenticator` and certificate-bound token mechanism parallel to RFC 7523 and DPoP. Tokens use `cnf.x5t#S256`; resource servers validate the presented certificate thumbprint. TLS termination boundaries and trusted proxy behavior must be explicit and testable.
