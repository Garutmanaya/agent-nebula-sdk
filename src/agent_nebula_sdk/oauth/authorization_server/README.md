# OAuth Authorization Server role

This module composes RFC-specific SDK services into Authorization Server workflows. It owns no HTTP routes, database schema, signing-key storage, or enterprise business policy.

Useful standards include RFC 7591/7592 client lifecycle, RFC 8414 metadata publication, RFC 7523 client authentication, RFC 8707 resource targeting, RFC 9068 token format, RFC 9449 DPoP, and RFC 9728 protected-resource metadata consumption.

**AGENT NEBULA ADDITIONAL FUNCTIONALITY:** Agent Nebula products may add enterprise client verification and AuthZEN policy decisions around these standard protocol operations. Those extensions must not alter the RFC wire contracts.
