"""Tests for the protocol runtime composition root and plugin registry."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_nebula_sdk.core.errors import ConfigurationError
from agent_nebula_sdk.runtime import ProtocolComponentRegistry, ProtocolRuntime


@dataclass(frozen=True)
class ExampleService:
    """Small component used to verify typed registry resolution."""

    value: str


@dataclass(frozen=True)
class ExamplePlugin:
    """Install one example extension into the runtime."""

    component: ExampleService

    @property
    def name(self) -> str:
        """Return the plugin identifier."""
        return "example.plugin"

    def install(self, registry: ProtocolComponentRegistry) -> None:
        """Register the example component."""
        registry.register("example.service", self.component)


def test_runtime_installs_and_resolves_additive_plugin() -> None:
    """Install a plugin without changing the runtime constructor."""
    service = ExampleService(value="ready")
    runtime = ProtocolRuntime(plugins=(ExamplePlugin(service),))

    assert runtime.registry.resolve("example.service", ExampleService) is service
    assert runtime.installed_plugins() == ("example.plugin",)


def test_runtime_rejects_duplicate_security_component() -> None:
    """Prevent plugins from silently replacing an existing component."""
    registry = ProtocolComponentRegistry()
    registry.register("oauth.example", ExampleService(value="first"))

    with pytest.raises(ConfigurationError) as exc_info:
        registry.register("oauth.example", ExampleService(value="second"))

    assert exc_info.value.code == "duplicate_protocol_component"


def test_runtime_reports_missing_standard_role() -> None:
    """Fail explicitly when an application requests an unconfigured role."""
    runtime = ProtocolRuntime()

    with pytest.raises(ConfigurationError) as exc_info:
        _ = runtime.client

    assert exc_info.value.code == "missing_protocol_component"


def test_registry_validates_names_types_and_iteration() -> None:
    """Cover registry diagnostics and deterministic component enumeration."""
    registry = ProtocolComponentRegistry()
    service = ExampleService(value="ready")
    registry.register("Example.Service", service)

    assert registry.contains("example.service") is True
    assert registry.names() == ("example.service",)
    assert tuple(registry) == ("example.service",)

    with pytest.raises(ConfigurationError) as type_error:
        registry.resolve("example.service", str)
    assert type_error.value.code == "invalid_protocol_component_type"

    with pytest.raises(ConfigurationError) as name_error:
        registry.contains("invalid name")
    assert name_error.value.code == "invalid_protocol_component_name"


def test_runtime_exposes_configured_standard_roles() -> None:
    """Return standard facades from one runtime composition root."""
    from agent_nebula_sdk.authorization_server import AuthorizationServerFacade
    from agent_nebula_sdk.client import OAuthClientFacade
    from agent_nebula_sdk.resource_server import ResourceServerFacade

    client = object.__new__(OAuthClientFacade)
    authorization_server = object.__new__(AuthorizationServerFacade)
    resource_server = object.__new__(ResourceServerFacade)
    runtime = ProtocolRuntime(
        client=client,
        authorization_server=authorization_server,
        resource_server=resource_server,
    )

    assert runtime.client is client
    assert runtime.authorization_server is authorization_server
    assert runtime.resource_server is resource_server
    assert runtime.resolve("oauth.client", OAuthClientFacade) is client


def test_installing_same_plugin_instance_is_idempotent() -> None:
    """Avoid duplicate installation when product wiring repeats one plugin."""
    plugin = ExamplePlugin(ExampleService(value="ready"))
    runtime = ProtocolRuntime()

    runtime.install(plugin)
    runtime.install(plugin)

    assert runtime.installed_plugins() == ("example.plugin",)
