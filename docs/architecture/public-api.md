# Public API Design

## Client role

```text
ClientSdk
├── register_client()
├── build_client_assertion()
├── request_access_token()
├── request_resource_token()
├── create_dpop_proof()
└── send_protected_request()
```

## Authorization-server role

```text
AuthorizationServerSdk
├── register_client()
├── authenticate_client()
├── validate_dpop_token_request()
├── resolve_resource()
├── issue_access_token()
├── authorization_server_metadata()
└── jwks_document()
```

## Resource-server role

```text
ResourceServerSdk
├── protected_resource_metadata()
├── validate_access_token()
├── validate_dpop_request()
└── build_security_context()
```

## API stability

Only modules re-exported through the role facades are public. Internal parser, validator, and codec classes may evolve without a major release.
