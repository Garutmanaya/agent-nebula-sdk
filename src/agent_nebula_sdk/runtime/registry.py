"""Namespaced component registry used by the SDK protocol runtime.

Purpose
-------
Provide one additive extension mechanism for future OAuth, A2A, MCP, identity,
and transport components without forcing the runtime to change its constructor
whenever a new protocol module is introduced.
"""

from __future__ import annotations

from collections.abc import Iterator
from threading import RLock
from typing import TypeVar

from agent_nebula_sdk.core.errors import ConfigurationError

T = TypeVar("T")


class ProtocolComponentRegistry:
    """Store immutable-by-name protocol components behind namespaced keys.

    Components are registered during application composition and resolved by
    consumers through stable names such as ``oauth.authorization_server`` or
    ``mcp.client_id_metadata``. Duplicate registration is rejected so one
    deployment cannot silently replace a security-critical implementation.
    """

    def __init__(self) -> None:
        """Create an empty, thread-safe component registry."""
        self._components: dict[str, object] = {}
        self._lock = RLock()

    def register(self, name: str, component: object) -> None:
        """Register one component under a normalized namespaced identifier.

        Parameters
        ----------
        name:
            Dot-separated component name.
        component:
            Configured protocol service, facade, adapter, or extension.

        Raises
        ------
        ConfigurationError
            If the name is malformed or already registered.
        """
        normalized = self._normalize_name(name)
        with self._lock:
            if normalized in self._components:
                raise ConfigurationError(
                    "protocol component is already registered",
                    code="duplicate_protocol_component",
                    details={"name": normalized},
                )
            self._components[normalized] = component

    def resolve(self, name: str, expected_type: type[T]) -> T:
        """Resolve one component and validate its runtime type."""
        normalized = self._normalize_name(name)
        with self._lock:
            component = self._components.get(normalized)
        if component is None:
            raise ConfigurationError(
                "protocol component is not configured",
                code="missing_protocol_component",
                details={"name": normalized},
            )
        if not isinstance(component, expected_type):
            raise ConfigurationError(
                "protocol component has an unexpected type",
                code="invalid_protocol_component_type",
                details={
                    "name": normalized,
                    "expected": expected_type.__name__,
                    "actual": type(component).__name__,
                },
            )
        return component

    def contains(self, name: str) -> bool:
        """Return whether a component is registered under the supplied name."""
        normalized = self._normalize_name(name)
        with self._lock:
            return normalized in self._components

    def names(self) -> tuple[str, ...]:
        """Return registered component names in deterministic order."""
        with self._lock:
            return tuple(sorted(self._components))

    def __iter__(self) -> Iterator[str]:
        """Iterate over a stable snapshot of registered component names."""
        return iter(self.names())

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Validate and normalize a dot-separated component identifier."""
        normalized = name.strip().lower()
        segments = normalized.split(".")
        if not normalized or any(not segment.replace("_", "").isalnum() for segment in segments):
            raise ConfigurationError(
                "protocol component name must contain dot-separated identifiers",
                code="invalid_protocol_component_name",
                details={"name": name},
            )
        return normalized
