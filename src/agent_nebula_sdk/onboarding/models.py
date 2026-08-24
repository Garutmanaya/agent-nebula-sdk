"""Immutable models for authenticated, multi-profile agent onboarding.

The models are protocol-neutral orchestration contracts. Normative OAuth,
A2A, MCP, JOSE, and TLS data remains owned by the existing SDK modules.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata, RegistrationRequest
from agent_nebula_sdk.oauth.rfc9728 import ProtectedResourceMetadata
from agent_nebula_sdk.onboarding.constants import (
    AgentRole,
    OnboardingAuthenticationMethod,
    RegistrationProfileType,
)


def _absolute_http_uri(value: str, field_name: str) -> str:
    """Validate an absolute HTTP(S) URI without imposing product network policy."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{field_name} must be an absolute HTTP(S) URI")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError(f"{field_name} must not contain user information or a fragment")
    return value


class OnboardingAuthenticationInput(BaseModel):
    """Carry one selected authentication method and its opaque credential."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: OnboardingAuthenticationMethod
    credential: str | None = Field(default=None, max_length=65536)

    @model_validator(mode="after")
    def validate_credential_presence(self) -> OnboardingAuthenticationInput:
        """Require credentials for protected methods and reject them for open mode."""
        if self.method is OnboardingAuthenticationMethod.OPEN and self.credential is not None:
            raise ValueError("open onboarding must not include a credential")
        if self.method is not OnboardingAuthenticationMethod.OPEN and not self.credential:
            raise ValueError(f"{self.method.value} onboarding requires a credential")
        return self


class OnboardingRequestContext(BaseModel):
    """Represent transport context needed by product authentication adapters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_headers: dict[str, str] = Field(default_factory=dict)
    remote_address: str | None = None
    peer_certificate: bytes | None = None


class OnboardingPrincipal(BaseModel):
    """Represent identity and trust established before profile processing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject: str | None = None
    authentication_method: OnboardingAuthenticationMethod
    trust_status: str = Field(min_length=1, max_length=80)
    provider_id: str | None = None
    agent_id: str | None = None
    credential_reference: str | None = None
    claims: dict[str, Any] = Field(default_factory=dict)


class AgentRegistrationInput(BaseModel):
    """Describe protocol-neutral Agent identity and discovery metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_card_uri: str
    protocols: frozenset[str] = frozenset()
    capabilities: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_agent_card_uri(self) -> AgentRegistrationInput:
        """Require an absolute Agent Card URI suitable for product-controlled resolution."""
        _absolute_http_uri(self.agent_card_uri, "agent_card_uri")
        return self


class OAuthClientRegistrationInput(BaseModel):
    """Wrap RFC 7591 client metadata for onboarding composition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metadata: ClientMetadata


class ProtectedResourceRegistrationInput(BaseModel):
    """Wrap RFC 9728 metadata with optional Agent discovery linkage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    metadata: ProtectedResourceMetadata
    metadata_uri: str | None = None
    agent_card_uri: str | None = None
    resource_type: str = Field(default="HTTP_API", min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_link_uris(self) -> ProtectedResourceRegistrationInput:
        """Validate optional publication URIs without duplicating RFC 9728 validation."""
        if self.metadata_uri is not None:
            _absolute_http_uri(self.metadata_uri, "metadata_uri")
        if self.agent_card_uri is not None:
            _absolute_http_uri(self.agent_card_uri, "agent_card_uri")
        return self


class OnboardingRequest(BaseModel):
    """Represent one atomic onboarding request containing one or more profiles."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_name: str = Field(min_length=1, max_length=255)
    roles: frozenset[AgentRole]
    authentication: OnboardingAuthenticationInput
    context: OnboardingRequestContext = OnboardingRequestContext()
    agent: AgentRegistrationInput | None = None
    oauth_client: OAuthClientRegistrationInput | None = None
    protected_resource: ProtectedResourceRegistrationInput | None = None
    declared_publisher: dict[str, Any] | None = None
    declared_provider: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_role_profile_consistency(self) -> OnboardingRequest:
        """Reject missing or undeclared profile data before authentication begins."""
        if not (self.agent or self.oauth_client or self.protected_resource):
            raise ValueError("at least one registration profile is required")
        if AgentRole.OAUTH_CLIENT in self.roles and self.oauth_client is None:
            raise ValueError("OAUTH_CLIENT role requires oauth_client profile")
        if AgentRole.OAUTH_CLIENT not in self.roles and self.oauth_client is not None:
            raise ValueError("oauth_client profile requires OAUTH_CLIENT role")
        if AgentRole.OAUTH_PROTECTED_RESOURCE in self.roles and self.protected_resource is None:
            raise ValueError("OAUTH_PROTECTED_RESOURCE role requires protected_resource profile")
        if (
            AgentRole.OAUTH_PROTECTED_RESOURCE not in self.roles
            and self.protected_resource is not None
        ):
            raise ValueError("protected_resource profile requires OAUTH_PROTECTED_RESOURCE role")
        if ({AgentRole.A2A_PROVIDER, AgentRole.A2A_CALLER} & self.roles) and self.agent is None:
            raise ValueError("A2A roles require an agent profile")
        return self


class PreparedRegistration(BaseModel):
    """Contain one validated profile payload ready for product persistence."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    profile_type: RegistrationProfileType
    payload: AgentRegistrationInput | RegistrationRequest | ProtectedResourceRegistrationInput


class PreparedOnboardingRegistration(BaseModel):
    """Contain the complete validated unit passed to an atomic transaction adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_name: str
    roles: frozenset[AgentRole]
    principal: OnboardingPrincipal
    registrations: tuple[PreparedRegistration, ...]
    declared_publisher: dict[str, Any] | None = None
    declared_provider: dict[str, Any] | None = None


class AgentProfileResult(BaseModel):
    """Return Agent database and stable external identifiers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str = Field(min_length=1, max_length=255)
    external_agent_id: str = Field(min_length=1, max_length=255)


class OAuthClientProfileResult(BaseModel):
    """Return internal and RFC-facing OAuth client identifiers distinctly."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    oauth_client_id: str = Field(min_length=1, max_length=255)
    client_id: str = Field(min_length=1, max_length=255)


class ProtectedResourceProfileResult(BaseModel):
    """Return internal and RFC 8707 protected-resource identifiers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    oauth_protected_resource_id: str = Field(min_length=1, max_length=255)
    resource_identifier: str = Field(min_length=1)


OnboardingProfileResult = (
    AgentProfileResult | OAuthClientProfileResult | ProtectedResourceProfileResult
)


class OnboardingCommitResult(BaseModel):
    """Represent typed identifiers from one created or resolved registration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    onboarding_id: str = Field(min_length=1, max_length=255)
    entity_id: str | None = None
    profiles: dict[RegistrationProfileType, OnboardingProfileResult] = Field(
        default_factory=dict
    )
    disposition: Literal["CREATED", "RESOLVED", "CLAIMED"] = "CREATED"
    committed_at: datetime


class OnboardingResult(BaseModel):
    """Return normalized authentication and persistence results to an application."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: OnboardingPrincipal
    commit: OnboardingCommitResult
    registered_profiles: tuple[RegistrationProfileType, ...]
