# RFC 8414 and RFC 9728 Conformance

## RFC 8414

Implemented:

- authorization-server metadata model
- issuer, token, JWKS, and registration endpoint validation
- path-insertion well-known URL construction
- exact returned issuer validation
- client-authentication and DPoP algorithm metadata
- unknown metadata member tolerance

Deferred:

- signed authorization-server metadata
- OpenID Connect Discovery fallback
- cache-control implementation

## RFC 9728

Implemented:

- full initial metadata registry model
- DPoP and mTLS capability members
- localized extension member preservation
- path-specific and root well-known discovery
- `resource_metadata` challenge support
- exact resource-identifier validation
- advertised authorization-server selection
- bounded JSON retrieval

Deferred:

- signed protected-resource metadata validation
- metadata cache implementation
- authorization-server/protected-resource cross-list policy
