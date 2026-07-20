"""Product-supplied ports used by the persistence-neutral onboarding module."""

from __future__ import annotations

from typing import Any, Protocol

from agent_nebula_sdk.onboarding.models import (
    OnboardingCommitResult,
    OnboardingPrincipal,
    PreparedOnboardingRegistration,
)


class ApiKeyVerifier(Protocol):
    """Verify an opaque product-managed onboarding API key."""

    def verify(self, credential: str) -> OnboardingPrincipal:
        """Return the principal bound to a valid API key or raise a stable SDK error."""
        ...


class InitialAccessTokenVerifier(Protocol):
    """Atomically verify and consume a controlled onboarding token."""

    def verify_and_consume(self, token: str) -> OnboardingPrincipal:
        """Return the token principal while preventing a second successful use."""
        ...


class AgentCardResolver(Protocol):
    """Resolve Agent Card content through a product-controlled network adapter."""

    def resolve(self, uri: str) -> dict[str, Any]:
        """Return parsed Agent Card content from the supplied absolute URI."""
        ...


class OnboardingTransactionPort(Protocol):
    """Persist all prepared profiles as one product-owned atomic transaction."""

    def commit(self, registration: PreparedOnboardingRegistration) -> OnboardingCommitResult:
        """Commit every profile or fail without leaving partial registration state."""
        ...


class OnboardingAuditSink(Protocol):
    """Receive security events without coupling the SDK to an audit database."""

    def record(self, event_name: str, attributes: dict[str, Any]) -> None:
        """Record one non-secret onboarding event through a product adapter."""
        ...
