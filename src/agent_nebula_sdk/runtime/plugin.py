"""Plugin contract for additive SDK protocol-runtime extensions."""

from __future__ import annotations

from typing import Protocol

from agent_nebula_sdk.runtime.registry import ProtocolComponentRegistry


class ProtocolRuntimePlugin(Protocol):
    """Install a self-contained protocol extension into a runtime registry.

    A plugin receives only the registry. Infrastructure construction remains
    explicit in the consuming application, preventing the SDK from creating
    hidden databases, HTTP clients, key stores, or global state.
    """

    @property
    def name(self) -> str:
        """Return a stable plugin identifier used for diagnostics."""

    def install(self, registry: ProtocolComponentRegistry) -> None:
        """Register all components owned by the plugin."""
