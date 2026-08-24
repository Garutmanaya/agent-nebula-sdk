# RFC 8414 — OAuth 2.0 Authorization Server Metadata

This module implements RFC 8414 metadata models, issuer validation, well-known URL construction, and metadata retrieval.

Agent Nebula uses RFC 8414 so OAuth clients and protected resources can discover an Authorization Server without hardcoded token, JWKS, or registration endpoints.

`protected_resources` is retained on the metadata model because RFC 9728 registers that optional extension in the RFC 8414 metadata registry.

No Agent Nebula-specific protocol semantics are added to RFC 8414.
