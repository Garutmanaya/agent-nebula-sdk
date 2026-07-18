"""Persistence-neutral ports required by RFC 8707 resource resolution.

The SDK owns protocol processing but not a database. Agent Nebula can implement
these ports with PostgreSQL, while SDK tests and small deployments can use the
in-memory reference adapter.
"""

from __future__ import annotations

from typing import Protocol

from agent_nebula_sdk.oauth.rfc8707.models import ResourceRegistration


class ResourceRegistry(Protocol):
    """Resolve protected-resource identifiers registered with the platform."""

    def find(self, resource: str) -> ResourceRegistration | None:
        """Return the active registration matching a resource or alias."""
        ...


class ResourceCanonicalizer(Protocol):
    """Canonicalize a resource identifier before lookup.

    RFC 8707 does not mandate URI normalization. Deployments that use aliases,
    host-name normalization, or tenant-aware identifiers can supply a plugin;
    the default implementation preserves the validated identifier exactly.
    """

    def canonicalize(self, resource: str) -> str:
        """Return the lookup representation for one validated resource URI."""
        ...
