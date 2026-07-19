"""Protocol-runtime plugin for MCP Client ID Metadata Documents."""

from __future__ import annotations

from dataclasses import dataclass

from agent_nebula_sdk.mcp.client_id_metadata.resolver import ClientIdMetadataResolver
from agent_nebula_sdk.runtime import ProtocolComponentRegistry

MCP_CLIENT_ID_METADATA_COMPONENT = "mcp.client_id_metadata"


@dataclass(frozen=True, slots=True)
class McpClientIdMetadataPlugin:
    """Install the current MCP client-identification resolver into a runtime."""

    resolver: ClientIdMetadataResolver

    @property
    def name(self) -> str:
        """Return the stable plugin identifier."""
        return MCP_CLIENT_ID_METADATA_COMPONENT

    def install(self, registry: ProtocolComponentRegistry) -> None:
        """Register the resolver under its public component name."""
        registry.register(MCP_CLIENT_ID_METADATA_COMPONENT, self.resolver)
