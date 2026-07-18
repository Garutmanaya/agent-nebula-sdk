"""Typed models for RFC 8707 resource indicators and audience mappings.

The RFC permits one or more ``resource`` parameter occurrences. The SDK models
that standards-level capability while allowing a deployment policy to restrict
a token request to one resource, which is the Agent Nebula Phase 1 profile.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ResourceIndicatorRequest(BaseModel):
    """Represent resource indicators carried by an OAuth request.

    Responsibility
    --------------
    Preserve the ordered resource values exactly as supplied by the client.
    URI validation and deployment restrictions are deliberately delegated to
    ``ResourceIndicatorValidator`` and ``ResourceResolutionService``.

    Standards
    ---------
    RFC 8707 Section 2 permits multiple ``resource`` parameter occurrences.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    resources: tuple[str, ...] = ()


class ResourceRegistration(BaseModel):
    """Describe one protected resource known to an authorization server.

    Responsibility
    --------------
    Map a client-facing resource identifier to the audience value that the
    future RFC 9068 token issuer will place in the access token.

    Standards
    ---------
    RFC 8707 Section 2 allows an authorization server to use the exact
    ``resource`` value as the audience or map it to another identifier.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource: str = Field(min_length=1, max_length=4096)
    audience: str = Field(min_length=1, max_length=4096)
    aliases: tuple[str, ...] = ()
    active: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ResolvedResource(BaseModel):
    """Return the canonical resource and audience selected by registry policy.

    Responsibility
    --------------
    Carry the immutable result of resource lookup from the RFC 8707 layer into
    token issuance without exposing persistence-specific records.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    requested_resource: str
    canonical_resource: str
    audience: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AudienceValidationResult(BaseModel):
    """Describe a successful resource-server audience validation decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_audience: str
    token_audiences: tuple[str, ...]
