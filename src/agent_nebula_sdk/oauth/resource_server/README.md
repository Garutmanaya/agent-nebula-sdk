# OAuth Resource Server role

This module composes access-token and proof-of-possession validation for an OAuth Resource Server. It does not own application authorization policy.

RFC 9728 metadata publication belongs to the protected resource; RFC 9068 and RFC 9449 provide token and DPoP validation primitives used by this role.

**AGENT NEBULA ADDITIONAL FUNCTIONALITY:** Agent providers may apply Agent Nebula policy after standards-based authentication has established the trusted caller context.
