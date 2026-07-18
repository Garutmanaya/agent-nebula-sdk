"""Reference adapters for RFC 8707 resource registration and resolution.

These adapters are intended for tests, examples, and small single-process
systems. Agent Nebula should provide a transactional PostgreSQL adapter through
the same ``ResourceRegistry`` port.
"""

from __future__ import annotations

from threading import RLock

from agent_nebula_sdk.oauth.rfc8707.models import ResourceRegistration


class ExactResourceCanonicalizer:
    """Preserve the validated resource identifier exactly as supplied."""

    def canonicalize(self, resource: str) -> str:
        """Return the resource unchanged because RFC 8707 defines no normalization."""
        return resource


class InMemoryResourceRegistry:
    """Store resource and alias mappings in a thread-safe in-memory registry.

    Responsibility
    --------------
    Provide a deterministic reference implementation of the persistence port.
    Duplicate primary resources and aliases are rejected to prevent ambiguous
    audience selection.
    """

    def __init__(self, registrations: tuple[ResourceRegistration, ...] = ()) -> None:
        """Create the registry and atomically install initial registrations."""
        self._lock = RLock()
        self._registrations: dict[str, ResourceRegistration] = {}
        for registration in registrations:
            self.register(registration)

    def register(self, registration: ResourceRegistration) -> None:
        """Add one resource and all aliases while enforcing uniqueness."""
        identifiers = (registration.resource, *registration.aliases)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("resource registration contains duplicate identifiers")
        with self._lock:
            collisions = sorted(
                identifier for identifier in identifiers if identifier in self._registrations
            )
            if collisions:
                raise ValueError(f"resource identifier already exists: {collisions[0]}")
            for identifier in identifiers:
                self._registrations[identifier] = registration

    def find(self, resource: str) -> ResourceRegistration | None:
        """Return an active registration matching the resource or an alias."""
        with self._lock:
            registration = self._registrations.get(resource)
            if registration is None or not registration.active:
                return None
            return registration
