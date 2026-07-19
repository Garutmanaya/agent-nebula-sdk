"""Application-facing protocol runtime and standard role composition.

Purpose
-------
Provide one dependency-injection boundary for configured SDK roles while
retaining the existing category-based package structure. The runtime does not
construct infrastructure or hide protocol dependencies.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

from agent_nebula_sdk.authorization_server import AuthorizationServerFacade
from agent_nebula_sdk.client import OAuthClientFacade
from agent_nebula_sdk.resource_server import ResourceServerFacade
from agent_nebula_sdk.runtime.plugin import ProtocolRuntimePlugin
from agent_nebula_sdk.runtime.registry import ProtocolComponentRegistry

CLIENT_ROLE = "oauth.client"
AUTHORIZATION_SERVER_ROLE = "oauth.authorization_server"
RESOURCE_SERVER_ROLE = "oauth.resource_server"

T = TypeVar("T")


class ProtocolRuntime:
    """Expose configured protocol roles and additive extension components.

    Responsibility
    --------------
    Act as a composition root shared by Agent Nebula and Agent Genesis. The
    runtime centralizes lookup and lifecycle ownership but leaves every RFC
    implementation in its existing top-level category package.

    Thread safety
    -------------
    Component registration and resolution are thread-safe. The thread-safety
    of resolved components depends on their injected collaborators.
    """

    def __init__(
        self,
        *,
        client: OAuthClientFacade | None = None,
        authorization_server: AuthorizationServerFacade | None = None,
        resource_server: ResourceServerFacade | None = None,
        plugins: Iterable[ProtocolRuntimePlugin] = (),
    ) -> None:
        """Create a runtime from already configured role facades and plugins."""
        self._registry = ProtocolComponentRegistry()
        if client is not None:
            self._registry.register(CLIENT_ROLE, client)
        if authorization_server is not None:
            self._registry.register(AUTHORIZATION_SERVER_ROLE, authorization_server)
        if resource_server is not None:
            self._registry.register(RESOURCE_SERVER_ROLE, resource_server)
        self._installed_plugins: list[str] = []
        for plugin in plugins:
            self.install(plugin)

    @property
    def registry(self) -> ProtocolComponentRegistry:
        """Return the extension registry for explicit application composition."""
        return self._registry

    @property
    def client(self) -> OAuthClientFacade:
        """Return the configured OAuth client role facade."""
        return self._registry.resolve(CLIENT_ROLE, OAuthClientFacade)

    @property
    def authorization_server(self) -> AuthorizationServerFacade:
        """Return the configured OAuth authorization-server role facade."""
        return self._registry.resolve(AUTHORIZATION_SERVER_ROLE, AuthorizationServerFacade)

    @property
    def resource_server(self) -> ResourceServerFacade:
        """Return the configured OAuth resource-server role facade."""
        return self._registry.resolve(RESOURCE_SERVER_ROLE, ResourceServerFacade)

    def install(self, plugin: ProtocolRuntimePlugin) -> None:
        """Install one plugin exactly once.

        Plugin installation is explicit and deterministic. A plugin cannot
        overwrite components because the registry rejects duplicate names.
        """
        if plugin.name in self._installed_plugins:
            return
        plugin.install(self._registry)
        self._installed_plugins.append(plugin.name)

    def resolve(self, name: str, expected_type: type[T]) -> T:
        """Resolve an extension component by namespaced identifier.

        Applications that need a strongly typed result should call the
        registry directly with the concrete expected type. This convenience
        method is intended for product composition and diagnostics code.
        """
        return self._registry.resolve(name, expected_type)

    def installed_plugins(self) -> tuple[str, ...]:
        """Return plugin names in installation order."""
        return tuple(self._installed_plugins)
