# RFC 7592 — OAuth 2.0 Dynamic Client Registration Management Protocol

This module implements RFC 7592 client registration lifecycle management on top of RFC 7591.

It provides:

- server-issued `registration_client_uri` and `registration_access_token`
- GET/read of current registration
- PUT/full replacement of registration metadata
- DELETE/deprovisioning
- registration access-token rotation
- pluggable persistence, token protection, update policy, and cleanup ports

The SDK does not define an Authorization Server database or HTTP framework routes.

Agent Nebula uses RFC 7592 to manage OAuth client lifecycle without creating a proprietary deregistration protocol.

No Agent Nebula-specific fields or wire behavior are added to RFC 7592.
