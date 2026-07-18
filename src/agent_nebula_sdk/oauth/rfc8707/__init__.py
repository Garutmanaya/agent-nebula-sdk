"""RFC 8707 Resource Indicators for OAuth 2.0.

Public APIs are grouped by role:

* client/transport: ``ResourceParameterCodec``;
* authorization server: ``ResourceResolutionService`` and validation policies;
* resource server: ``ResourceAudienceValidator``;
* persistence: ``ResourceRegistry`` port and in-memory reference adapter.
"""

from agent_nebula_sdk.oauth.rfc8707.adapters import (
    ExactResourceCanonicalizer,
    InMemoryResourceRegistry,
)
from agent_nebula_sdk.oauth.rfc8707.audience import ResourceAudienceValidator
from agent_nebula_sdk.oauth.rfc8707.codec import ResourceParameterCodec
from agent_nebula_sdk.oauth.rfc8707.constants import INVALID_TARGET_ERROR, RESOURCE_PARAMETER
from agent_nebula_sdk.oauth.rfc8707.models import (
    AudienceValidationResult,
    ResolvedResource,
    ResourceIndicatorRequest,
    ResourceRegistration,
)
from agent_nebula_sdk.oauth.rfc8707.policy import (
    PriorGrantResourcePolicy,
    ResourceIndicatorPolicy,
    ResourceIndicatorValidator,
)
from agent_nebula_sdk.oauth.rfc8707.ports import ResourceCanonicalizer, ResourceRegistry
from agent_nebula_sdk.oauth.rfc8707.service import ResourceResolutionService

__all__ = [
    "INVALID_TARGET_ERROR",
    "RESOURCE_PARAMETER",
    "AudienceValidationResult",
    "ExactResourceCanonicalizer",
    "InMemoryResourceRegistry",
    "PriorGrantResourcePolicy",
    "ResolvedResource",
    "ResourceAudienceValidator",
    "ResourceCanonicalizer",
    "ResourceIndicatorPolicy",
    "ResourceIndicatorRequest",
    "ResourceIndicatorValidator",
    "ResourceParameterCodec",
    "ResourceRegistration",
    "ResourceRegistry",
    "ResourceResolutionService",
]
