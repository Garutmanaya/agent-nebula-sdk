# Key Lifecycle

The SDK distinguishes four key purposes:

1. RFC 7523 client-authentication key.
2. RFC 9449 DPoP key.
3. TLS/mTLS key.
4. Agent Card signing key.

Keys must not be silently reused across purposes. The SDK models key purpose explicitly and rejects incompatible usage metadata.

Private keys are provided through `PrivateKeyProvider`; only public JWKs and metadata enter registry storage.
