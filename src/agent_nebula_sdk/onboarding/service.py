"""Top-level orchestration entry point for secure multi-profile onboarding."""

from __future__ import annotations

from agent_nebula_sdk.onboarding.models import (
    OnboardingRequest,
    OnboardingResult,
    PreparedOnboardingRegistration,
)
from agent_nebula_sdk.onboarding.ports import OnboardingAuditSink, OnboardingTransactionPort
from agent_nebula_sdk.onboarding.registry import OnboardingComponentRegistry


class OnboardingService:
    """Authenticate, validate, prepare, and atomically commit onboarding requests.

    Authentication is intentionally completed before profile processing or
    remote metadata resolution. Every profile is prepared before the product
    transaction port is called, preventing partial multi-role registration.
    """

    def __init__(
        self,
        *,
        registry: OnboardingComponentRegistry,
        transaction: OnboardingTransactionPort,
        audit_sink: OnboardingAuditSink | None = None,
    ) -> None:
        """Configure explicit components and the product-owned atomic transaction port."""
        self._registry = registry
        self._transaction = transaction
        self._audit_sink = audit_sink


    def resolve(self, request: OnboardingRequest) -> OnboardingResult | None:
        """Authenticate and resolve an existing registration without mutation."""
        authenticator = self._registry.authenticator(request.authentication.method)
        principal = authenticator.authenticate(request)
        prepared = tuple(
            profile.prepare(request, principal)
            for profile in self._registry.profiles()
            if profile.applies_to(request)
        )
        registration = PreparedOnboardingRegistration(
            entity_name=request.entity_name,
            roles=request.roles,
            principal=principal,
            registrations=prepared,
            declared_publisher=request.declared_publisher,
            declared_provider=request.declared_provider,
        )
        commit = self._transaction.resolve(registration)
        if commit is None:
            return None
        if self._audit_sink is not None:
            self._audit_sink.record(
                "onboarding.resolved",
                {
                    "onboarding_id": commit.onboarding_id,
                    "authentication_method": principal.authentication_method.value,
                    "profiles": [item.profile_type.value for item in prepared],
                },
            )
        return OnboardingResult(
            principal=principal,
            commit=commit,
            registered_profiles=tuple(item.profile_type for item in prepared),
        )

    def onboard(self, request: OnboardingRequest) -> OnboardingResult:
        """Process one atomic onboarding request.

        Args:
            request: Immutable request declaring authentication, roles, and profiles.

        Returns:
            Normalized principal and application-assigned registration identifiers.

        Raises:
            ConfigurationError: When a selected component is not configured.
            OnboardingAuthenticationError: When authentication fails.
            RegistrationProfileError: When any profile cannot be prepared.
            OnboardingCommitError: When the product adapter cannot commit atomically.
        """
        authenticator = self._registry.authenticator(request.authentication.method)
        principal = authenticator.authenticate(request)
        prepared = tuple(
            profile.prepare(request, principal)
            for profile in self._registry.profiles()
            if profile.applies_to(request)
        )
        registration = PreparedOnboardingRegistration(
            entity_name=request.entity_name,
            roles=request.roles,
            principal=principal,
            registrations=prepared,
            declared_publisher=request.declared_publisher,
            declared_provider=request.declared_provider,
        )
        commit = self._transaction.commit(registration)
        if self._audit_sink is not None:
            self._audit_sink.record(
                "onboarding.completed",
                {
                    "onboarding_id": commit.onboarding_id,
                    "authentication_method": principal.authentication_method.value,
                    "profiles": [item.profile_type.value for item in prepared],
                },
            )
        return OnboardingResult(
            principal=principal,
            commit=commit,
            registered_profiles=tuple(item.profile_type for item in prepared),
        )
