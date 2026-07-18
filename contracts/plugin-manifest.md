# Plugin Manifest Contract

Every plugin declares:

```yaml
id: private_key_jwt
version: 1
standards:
  - RFC7523
roles:
  - authorization_server
configuration_model: PrivateKeyJwtConfiguration
required_ports:
  - ClientRegistrationStore
  - ClientKeyResolver
  - ReplayStore
incompatible_plugins: []
startup_validator: validate_private_key_jwt_profile
```

The composition root rejects missing, duplicate, incompatible, or unsupported plugins before serving requests.
