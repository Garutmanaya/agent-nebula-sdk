"""Explicit registries for onboarding strategies and registration profiles."""

from agent_nebula_sdk.core.errors import ConfigurationError
from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.constants import (
    OnboardingAuthenticationMethod,
    RegistrationProfileType,
)
from agent_nebula_sdk.onboarding.registration_profiles.base import RegistrationProfile


class OnboardingComponentRegistry:
    """Resolve configured onboarding components without reflection or silent replacement."""

    def __init__(self) -> None:
        """Create an empty registry populated by the application composition root."""
        self._authenticators: dict[OnboardingAuthenticationMethod, OnboardingAuthenticator] = {}
        self._profiles: dict[RegistrationProfileType, RegistrationProfile] = {}

    def register_authenticator(self, authenticator: OnboardingAuthenticator) -> None:
        """Register one authentication strategy and reject duplicate method ownership."""
        if authenticator.method in self._authenticators:
            raise ConfigurationError(
                "onboarding authenticator is already registered",
                code="duplicate_onboarding_authenticator",
                details={"method": authenticator.method.value},
            )
        self._authenticators[authenticator.method] = authenticator

    def register_profile(self, profile: RegistrationProfile) -> None:
        """Register one profile handler and reject duplicate profile ownership."""
        if profile.profile_type in self._profiles:
            raise ConfigurationError(
                "onboarding registration profile is already registered",
                code="duplicate_onboarding_profile",
                details={"profile": profile.profile_type.value},
            )
        self._profiles[profile.profile_type] = profile

    def authenticator(self, method: OnboardingAuthenticationMethod) -> OnboardingAuthenticator:
        """Resolve the configured authentication strategy or fail during execution."""
        component = self._authenticators.get(method)
        if component is None:
            raise ConfigurationError(
                "onboarding authentication method is not configured",
                code="onboarding_authenticator_not_configured",
                details={"method": method.value},
            )
        return component

    def profiles(self) -> tuple[RegistrationProfile, ...]:
        """Return profile handlers in deterministic registration order."""
        return tuple(self._profiles.values())
