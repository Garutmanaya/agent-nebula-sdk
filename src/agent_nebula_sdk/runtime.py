"""Explicit composition root for configured Agent Nebula SDK protocol components."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, TypeVar

from agent_nebula_sdk.core.errors import ConfigurationError

T = TypeVar("T")


class ProtocolRuntimePlugin(Protocol):
    """Install one or more namespaced components into a protocol runtime."""

    @property
    def name(self) -> str:
        """Return the stable plugin name used for diagnostics."""
        ...

    def install(self, registry: ProtocolComponentRegistry) -> None:
        """Install namespaced components without replacing prior registrations."""
        ...


class ProtocolComponentRegistry:
    """Type-safe namespaced registry that rejects silent component replacement."""

    def __init__(self) -> None:
        self._components: dict[str, object] = {}

    def register(self, name: str, component: object) -> None:
        """Register one namespaced component and reject duplicate names."""
        if not name.strip():
            raise ConfigurationError(
                "protocol component name must not be empty",
                code="invalid_component_name",
            )
        if name in self._components:
            raise ConfigurationError(
                "protocol component is already registered",
                code="duplicate_component",
                details={"name": name},
            )
        self._components[name] = component

    def resolve(self, name: str, expected_type: type[T]) -> T:
        """Resolve one component and enforce its expected runtime type."""
        component = self._components.get(name)
        if component is None:
            raise ConfigurationError(
                "protocol component is not configured",
                code="component_not_configured",
                details={"name": name},
            )
        if not isinstance(component, expected_type):
            raise ConfigurationError(
                "protocol component has an unexpected type",
                code="component_type_mismatch",
                details={"name": name, "expected_type": expected_type.__name__},
            )
        return component


class ProtocolRuntime:
    """Product-owned composition boundary for SDK facades and additive plugins."""

    def __init__(self, *, plugins: Iterable[ProtocolRuntimePlugin] = ()) -> None:
        self.registry = ProtocolComponentRegistry()
        for plugin in plugins:
            plugin.install(self.registry)
