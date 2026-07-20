"""Object-oriented authentication contract for onboarding strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent_nebula_sdk.onboarding.constants import OnboardingAuthenticationMethod
from agent_nebula_sdk.onboarding.models import OnboardingPrincipal, OnboardingRequest


class OnboardingAuthenticator(ABC):
    """Authenticate one onboarding request without processing registration profiles."""

    @property
    @abstractmethod
    def method(self) -> OnboardingAuthenticationMethod:
        """Return the stable method identifier handled by this strategy."""

    @abstractmethod
    def authenticate(self, request: OnboardingRequest) -> OnboardingPrincipal:
        """Authenticate the request or raise ``OnboardingAuthenticationError``."""
