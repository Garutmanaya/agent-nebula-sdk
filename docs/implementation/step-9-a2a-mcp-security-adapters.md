# Step 9 — A2A and MCP Security Adapters

## Goal

Connect the completed OAuth client and resource-server roles to A2A and MCP
without creating custom token formats or embedding identity into protocol
payloads.

## A2A flow

```mermaid
sequenceDiagram
    participant Host as A2A Client / Host
    participant Nebula as Authorization Server
    participant Provider as A2A Server

    Host->>Provider: GET Agent Card
    Provider-->>Host: securitySchemes + security + resource identifier
    Host->>Nebula: RFC 7523 + RFC 8707 + DPoP token request
    Nebula-->>Host: RFC 9068 token bound with cnf.jkt
    Host->>Provider: A2A HTTP request + Authorization: DPoP + DPoP proof
    Provider->>Provider: Validate issuer, audience, token, htm, htu, ath, replay
    Provider->>Provider: Apply local capability policy
    Provider-->>Host: A2A response
```

## MCP discovery flow

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant Server as Protected MCP Server
    participant Auth as Authorization Server

    Client->>Server: Protected MCP request without token
    Server-->>Client: 401 + WWW-Authenticate resource_metadata URL
    Client->>Server: GET RFC 9728 metadata
    Server-->>Client: resource + authorization_servers
    Client->>Auth: GET RFC 8414 metadata
    Auth-->>Client: token endpoint, registration endpoint, algorithms
    Client->>Auth: Obtain resource-bound token
    Client->>Server: MCP request with DPoP token and proof
```

## Security boundaries

- A2A and MCP adapters never authorize business operations.
- Provider-local policy receives a trusted `ResourceSecurityContext`.
- Metadata resource and issuer identifiers are matched exactly.
- All discovery URLs use HTTPS and are fetched through an injected transport.
- Redirect, DNS, and network-egress policy remain deployment responsibilities.
