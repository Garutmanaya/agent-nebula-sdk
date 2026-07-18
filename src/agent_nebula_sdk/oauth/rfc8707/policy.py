"""Validation and authorization policies for RFC 8707 resource indicators.

This module separates normative URI validation from deployment-specific policy.
RFC 8707 permits multiple resources and abstract absolute URIs. Agent Nebula's
Phase 1 profile can require HTTPS and exactly one resource without weakening the
reusable standards implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8707.constants import INVALID_TARGET_ERROR


@dataclass(frozen=True, slots=True)
class ResourceIndicatorPolicy:
    """Configure accepted URI forms and resource-count restrictions.

    Parameters
    ----------
    require_resource:
        Reject requests that omit ``resource`` rather than applying a product
        default, as permitted by RFC 8707 Section 2.1.
    minimum_resources / maximum_resources:
        Bound resource multiplicity. ``maximum_resources=1`` implements the
        safer single-audience profile encouraged by RFC 8707 Section 3.
    allowed_schemes:
        Restrict URI schemes. ``None`` accepts any absolute URI scheme as the
        RFC allows; ``frozenset({"https"})`` is the Agent Nebula profile.
    allow_query:
        Permit a query component. RFC 8707 says it SHOULD NOT be present but
        recognizes valid deployments that require it.
    allow_userinfo:
        Permit URI user information. It is disabled by default because it is
        unnecessary for resource identity and can create ambiguous displays.
    """

    require_resource: bool = True
    minimum_resources: int = 1
    maximum_resources: int | None = 1
    allowed_schemes: frozenset[str] | None = frozenset({"https"})
    allow_query: bool = True
    allow_userinfo: bool = False
    maximum_uri_length: int = 4096

    def __post_init__(self) -> None:
        """Reject internally inconsistent policy configuration."""
        if self.minimum_resources < 0:
            raise ValueError("minimum_resources must not be negative")
        if self.maximum_resources is not None and self.maximum_resources < 1:
            raise ValueError("maximum_resources must be positive when configured")
        if self.maximum_resources is not None and self.minimum_resources > self.maximum_resources:
            raise ValueError("minimum_resources must not exceed maximum_resources")
        if self.maximum_uri_length < 1:
            raise ValueError("maximum_uri_length must be positive")


class ResourceIndicatorValidator:
    """Validate RFC 8707 resource parameter values under an active policy.

    Responsibility
    --------------
    Enforce absolute-URI syntax, fragment prohibition, duplicate rejection,
    resource-count limits, and configured security-profile restrictions.

    Standards
    ---------
    RFC 8707 Section 2 defines the resource URI requirements and
    ``invalid_target`` error. RFC 8707 Section 3 encourages single-resource
    tokens when the involved resources do not have a high degree of trust.
    """

    def __init__(self, policy: ResourceIndicatorPolicy | None = None) -> None:
        """Create a validator using the secure Agent Nebula default profile."""
        self._policy = policy or ResourceIndicatorPolicy()

    def validate(self, resources: tuple[str, ...]) -> tuple[str, ...]:
        """Validate resource values and return them without semantic rewriting.

        The RFC treats the URI as an identifier. This method intentionally does
        not strip paths, change trailing slashes, or otherwise guess equivalence;
        optional canonicalization belongs to a configured resolver plugin.
        """
        self._validate_count(resources)

        validated: list[str] = []
        observed: set[str] = set()
        for resource in resources:
            self._validate_uri(resource)
            if resource in observed:
                self._invalid_target(
                    "duplicate resource indicators are not accepted",
                    details={"resource": resource},
                )
            observed.add(resource)
            validated.append(resource)
        return tuple(validated)

    def _validate_count(self, resources: tuple[str, ...]) -> None:
        """Apply missing-resource and multiplicity policy."""
        count = len(resources)
        minimum = self._policy.minimum_resources if self._policy.require_resource else 0
        if count < minimum:
            self._invalid_target("a resource indicator is required")
        maximum = self._policy.maximum_resources
        if maximum is not None and count > maximum:
            self._invalid_target(
                "too many resource indicators were requested",
                details={"maximum_resources": maximum, "requested_resources": count},
            )

    def _validate_uri(self, resource: str) -> None:
        """Apply RFC 8707 absolute-URI and fragment requirements."""
        if not resource or resource != resource.strip():
            self._invalid_target("resource must be a non-empty URI without surrounding whitespace")
        if len(resource) > self._policy.maximum_uri_length:
            self._invalid_target(
                "resource URI exceeds the configured length limit",
                details={"maximum_uri_length": self._policy.maximum_uri_length},
            )

        parsed = urlsplit(resource)
        if not parsed.scheme:
            self._invalid_target("resource must be an absolute URI")
        if parsed.fragment:
            self._invalid_target("resource URI must not contain a fragment")
        if not self._policy.allow_query and parsed.query:
            self._invalid_target("resource URI query components are not accepted")
        if not self._policy.allow_userinfo and parsed.username is not None:
            self._invalid_target("resource URI user information is not accepted")

        allowed_schemes = self._policy.allowed_schemes
        if allowed_schemes is not None and parsed.scheme.lower() not in allowed_schemes:
            self._invalid_target(
                "resource URI scheme is not accepted",
                details={"allowed_schemes": sorted(allowed_schemes)},
            )
        if parsed.scheme.lower() in {"http", "https"} and not parsed.netloc:
            self._invalid_target("HTTP resource URI must include an authority")

    @staticmethod
    def _invalid_target(
        message: str,
        *,
        details: dict[str, object] | None = None,
    ) -> None:
        """Raise the RFC 8707 registered OAuth error."""
        raise ProtocolValidationError(
            message,
            code=INVALID_TARGET_ERROR,
            details=details,
        )


class PriorGrantResourcePolicy:
    """Restrict token-request resources to the resources in an earlier grant.

    RFC 8707 Section 2.2 permits authorization-code and refresh-token requests
    to select only resources originally granted, or a subset of them. This
    policy is reusable by the future token endpoint implementation.
    """

    def validate_subset(
        self,
        requested_resources: tuple[str, ...],
        granted_resources: tuple[str, ...] | None,
    ) -> None:
        """Reject a token request that expands beyond an existing grant."""
        if granted_resources is None:
            return
        ungranted = sorted(set(requested_resources) - set(granted_resources))
        if ungranted:
            raise ProtocolValidationError(
                "requested resource was not included in the original grant",
                code=INVALID_TARGET_ERROR,
                details={"ungranted_resources": ungranted},
            )
