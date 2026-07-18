"""Authorization-server resource resolution for RFC 8707.

The service validates client-provided resource indicators, constrains them to
any earlier authorization grant, resolves registered protected resources, and
returns the exact audiences required by the future RFC 9068 token issuer.
"""

from __future__ import annotations

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8707.constants import INVALID_TARGET_ERROR
from agent_nebula_sdk.oauth.rfc8707.models import (
    ResolvedResource,
    ResourceIndicatorRequest,
)
from agent_nebula_sdk.oauth.rfc8707.policy import (
    PriorGrantResourcePolicy,
    ResourceIndicatorValidator,
)
from agent_nebula_sdk.oauth.rfc8707.ports import ResourceCanonicalizer, ResourceRegistry


class ResourceResolutionService:
    """Resolve RFC 8707 resource indicators into token audience values.

    Responsibility
    --------------
    Coordinate standards validation, prior-grant restrictions, optional
    canonicalization, and protected-resource lookup without knowing how
    Agent Nebula persists provider registrations.

    Standards
    ---------
    RFC 8707 Sections 2, 2.2, and 3.
    """

    def __init__(
        self,
        *,
        registry: ResourceRegistry,
        validator: ResourceIndicatorValidator,
        canonicalizer: ResourceCanonicalizer,
        prior_grant_policy: PriorGrantResourcePolicy | None = None,
    ) -> None:
        """Inject the product-owned registry and all replaceable policies."""
        self._registry = registry
        self._validator = validator
        self._canonicalizer = canonicalizer
        self._prior_grant_policy = prior_grant_policy or PriorGrantResourcePolicy()

    def resolve(
        self,
        request: ResourceIndicatorRequest,
        *,
        granted_resources: tuple[str, ...] | None = None,
    ) -> tuple[ResolvedResource, ...]:
        """Resolve each requested resource or raise RFC 8707 ``invalid_target``.

        Parameters
        ----------
        request:
            Resource indicators parsed from an authorization or token request.
        granted_resources:
            Resources attached to an earlier authorization code or refresh-token
            grant. When supplied, the requested set must be a subset.
        """
        validated = self._validator.validate(request.resources)
        self._prior_grant_policy.validate_subset(validated, granted_resources)

        resolved: list[ResolvedResource] = []
        for requested_resource in validated:
            lookup_resource = self._canonicalizer.canonicalize(requested_resource)
            registration = self._registry.find(lookup_resource)
            if registration is None:
                raise ProtocolValidationError(
                    "requested resource is unknown or inactive",
                    code=INVALID_TARGET_ERROR,
                    details={"resource": requested_resource},
                )
            resolved.append(
                ResolvedResource(
                    requested_resource=requested_resource,
                    canonical_resource=registration.resource,
                    audience=registration.audience,
                    metadata=registration.metadata,
                )
            )
        return tuple(resolved)

    def resolve_single_audience(
        self,
        request: ResourceIndicatorRequest,
        *,
        granted_resources: tuple[str, ...] | None = None,
    ) -> str:
        """Return the one audience required by Agent Nebula's Phase 1 profile."""
        resolved = self.resolve(request, granted_resources=granted_resources)
        if len(resolved) != 1:
            raise ProtocolValidationError(
                "the configured token profile requires exactly one resource",
                code=INVALID_TARGET_ERROR,
                details={"resolved_resources": len(resolved)},
            )
        return resolved[0].audience
