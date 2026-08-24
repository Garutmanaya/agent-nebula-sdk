# OAuth Client role

This module composes OAuth client workflows from RFC-specific components. It performs no implicit key persistence and uses injected transports for network operations.

Current standards include RFC 7591 registration, RFC 7592 registration management, RFC 7523 `private_key_jwt`, RFC 8414 metadata discovery, RFC 8707 resource indicators, RFC 9449 DPoP, and RFC 9728 protected-resource metadata discovery.

**AGENT NEBULA ADDITIONAL FUNCTIONALITY:** Enterprise clients may carry Agent Nebula enrollment evidence in addition to standards-compliant OAuth registration. The underlying RFC behavior remains unchanged.
