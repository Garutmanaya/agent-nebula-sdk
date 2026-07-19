# Testing Standards

Every public API requires unit tests. Every external HTTP operation requires success, timeout, TLS/connection, non-JSON, invalid JSON, 4xx, 5xx, size-limit, and malformed-metadata coverage as applicable. Security modules require replay, tampering, algorithm, issuer, audience, expiry, and key-rotation tests. Cross-role flows require acceptance tests.
