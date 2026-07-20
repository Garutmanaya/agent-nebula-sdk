"""ProtocolRuntime plugin exposing onboarding components through stable names."""

from dataclasses import dataclass

from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.registration_profiles.base import RegistrationProfile
from agent_nebula_sdk.onboarding.service import OnboardingService
from agent_nebula_sdk.runtime import ProtocolComponentRegistry


@dataclass(frozen=True)
class OnboardingRuntimePlugin:
    """Install a configured onboarding service and its pluggable components."""

    service: OnboardingService
    authenticators: tuple[OnboardingAuthenticator, ...] = ()
    profiles: tuple[RegistrationProfile, ...] = ()

    @property
    def name(self) -> str:
        """Return the stable runtime plugin name."""
        return "onboarding"

    def install(self, registry: ProtocolComponentRegistry) -> None:
        """Register configured components without replacing existing runtime entries."""
        registry.register("onboarding.service", self.service)
        for authenticator in self.authenticators:
            registry.register(
                f"onboarding.authentication.{authenticator.method.value.lower()}",
                authenticator,
            )
        for profile in self.profiles:
            registry.register(
                f"onboarding.profile.{profile.profile_type.value.lower()}",
                profile,
            )
