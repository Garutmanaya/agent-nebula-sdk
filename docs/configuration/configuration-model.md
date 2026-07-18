# Configuration Model

The SDK receives validated configuration objects; it does not read product INI files or environment variables directly.

```text
SdkConfiguration
├── algorithm_policy
├── clock_policy
├── http_policy
├── metadata_policy
├── registration_policy
├── client_authentication
├── resource_indicators
├── access_token_profile
├── sender_constraint
├── key_rotation_policy
└── protocol_plugins
```

## Example product configuration

```ini
[sdk.client_authentication]
plugin=private_key_jwt
allowed_algorithms=ES256
assertion_lifetime_seconds=300

[sdk.registration]
plugin=rfc7591
profile=open

[sdk.resource_indicator]
plugin=rfc8707
single_resource_only=true

[sdk.access_token]
plugin=rfc9068
lifetime_seconds=600

[sdk.sender_constraint]
plugin=dpop
replay_window_seconds=300
nonce_mode=optional
```

Secrets and private-key locations belong to products and are injected through ports.
