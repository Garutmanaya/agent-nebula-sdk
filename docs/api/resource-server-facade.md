# Resource-Server Facade

The resource-server facade validates RFC 9068 tokens, exact issuer and audience, DPoP proof binding, HTTP method and URI, access-token hash, nonce, and replay state. It returns a trusted security context. Provider-local authorization occurs after this facade returns successfully.
