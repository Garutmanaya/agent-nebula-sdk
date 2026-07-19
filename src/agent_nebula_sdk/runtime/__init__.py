"""Protocol runtime composition root and plugin registry."""

from agent_nebula_sdk.runtime.plugin import ProtocolRuntimePlugin
from agent_nebula_sdk.runtime.registry import ProtocolComponentRegistry
from agent_nebula_sdk.runtime.runtime import (
    AUTHORIZATION_SERVER_ROLE,
    CLIENT_ROLE,
    RESOURCE_SERVER_ROLE,
    ProtocolRuntime,
)

__all__ = [
    "AUTHORIZATION_SERVER_ROLE",
    "CLIENT_ROLE",
    "RESOURCE_SERVER_ROLE",
    "ProtocolComponentRegistry",
    "ProtocolRuntime",
    "ProtocolRuntimePlugin",
]
