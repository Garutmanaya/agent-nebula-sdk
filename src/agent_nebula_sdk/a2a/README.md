# A2A Security Adapters

This package integrates the SDK's OAuth security profile with the A2A protocol.
A2A authentication remains an HTTP/TLS concern; credentials are never placed in
A2A messages or Agent Cards.

## Implemented

- Agent Card OAuth2 `securitySchemes` and `security` fragments
- RFC 9728 resource association
- DPoP-authenticated HTTP request construction
- server-side RFC 9068 and RFC 9449 authentication delegation
- `application/a2a+json` transport support

## Not implemented here

A2A tasks, messages, skills, streaming, push notifications, JSON-RPC dispatch,
and provider-local authorization remain separate modules or product code.
