# Step 6 — RFC 9068 JWT Access Tokens

## Flow

```mermaid
sequenceDiagram
    participant H as Host Client
    participant N as Agent Nebula Authorization Server
    participant P as Provider Resource Server
    H->>N: Token request + RFC 8707 resource
    N->>N: Resolve one audience
    N->>N: Build required RFC 9068 claims
    N-->>H: Signed typ=at+jwt token
    H->>P: Authorization token
    P->>P: Resolve Nebula key by iss + kid
    P->>P: Validate typ, alg, signature, iss, aud, exp
    P-->>H: Authenticated security context
```

The issuer and validator are persistence-neutral. Agent Nebula supplies private
signing keys and Provider Agents resolve public keys from Nebula JWKS metadata.
