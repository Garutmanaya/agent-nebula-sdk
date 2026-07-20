"""Object-oriented contract for independent onboarding registration profiles."""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent_nebula_sdk.onboarding.constants import RegistrationProfileType
from agent_nebula_sdk.onboarding.models import (
    OnboardingPrincipal,
    OnboardingRequest,
    PreparedRegistration,
)


class RegistrationProfile(ABC):
    """Validate and prepare one registration target without owning persistence."""

    @property
    @abstractmethod
    def profile_type(self) -> RegistrationProfileType:
        """Return the stable profile identifier handled by this component."""

    @abstractmethod
    def applies_to(self, request: OnboardingRequest) -> bool:
        """Return whether the request contains this registration profile."""

    @abstractmethod
    def prepare(
        self,
        request: OnboardingRequest,
        principal: OnboardingPrincipal,
    ) -> PreparedRegistration:
        """Validate and return a persistence-neutral prepared registration."""
