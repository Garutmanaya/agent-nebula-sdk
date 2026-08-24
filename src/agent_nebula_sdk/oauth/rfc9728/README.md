# RFC 9728 — OAuth 2.0 Protected Resource Metadata

This module implements RFC 9728 protected-resource metadata models, well-known discovery, metadata retrieval, exact resource matching, and `WWW-Authenticate` `resource_metadata` challenge support.

Agent Nebula uses RFC 9728 to describe OAuth protection for registered Agent resources without making the OAuth Authorization Server the owner of Agent metadata.

The Agent Registry remains authoritative for Agent and resource information; OAuth components consume the standard RFC 9728 representation.

No Agent Nebula-specific fields are added to the RFC 9728 model.
