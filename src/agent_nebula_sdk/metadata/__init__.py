"""OAuth metadata publication, discovery, and challenge support."""

from agent_nebula_sdk.metadata.challenge import OAuthChallenge, OAuthChallengeCodec
from agent_nebula_sdk.metadata.discovery import (
    OAuthMetadataClient,
    authorization_server_metadata_url,
    openid_configuration_urls,
    protected_resource_metadata_urls,
)
from agent_nebula_sdk.metadata.models import AuthorizationServerMetadata, ProtectedResourceMetadata

__all__ = [
    "AuthorizationServerMetadata",
    "OAuthChallenge",
    "OAuthChallengeCodec",
    "OAuthMetadataClient",
    "ProtectedResourceMetadata",
    "authorization_server_metadata_url",
    "openid_configuration_urls",
    "protected_resource_metadata_urls",
]
