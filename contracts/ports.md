# Port Contracts

## ClientRegistrationStore

- create registration atomically;
- retrieve by stable client identifier;
- update status with optimistic concurrency;
- list active public-key references.

## ClientKeyResolver

- resolve by client identifier and `kid`;
- return key status and validity window;
- support bounded JWKS refresh;
- never return private material.

## ResourceRegistry

- resolve canonical RFC 8707 resource URI;
- return one active resource and expected audience;
- reject aliases unless explicitly registered.

## ReplayStore

- atomically consume a namespaced identifier;
- distinguish first use from replay;
- retain until protocol-specific expiration;
- support concurrency across instances.

## TrustClaimProvider

- return registry-governed claims only;
- never return provider-specific business permissions.

## PrivateKeyProvider

- sign without exposing raw private material where possible;
- identify key purpose and `kid`;
- support rotation and hardware-backed implementations.
