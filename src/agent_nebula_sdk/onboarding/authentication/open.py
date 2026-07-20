"""Open onboarding authentication for explicitly untrusted registrations."""

from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.constants import OnboardingAuthenticationMethod
from agent_nebula_sdk.onboarding.errors import OnboardingAuthenticationError
from agent_nebula_sdk.onboarding.models import OnboardingPrincipal, OnboardingRequest


class OpenOnboardingAuthenticator(OnboardingAuthenticator):
    """Establish an anonymous, unverified principal without accepting credentials."""

    @property
    def method(self) -> OnboardingAuthenticationMethod:
        """Return the open authentication identifier."""
        return OnboardingAuthenticationMethod.OPEN

    def authenticate(self, request: OnboardingRequest) -> OnboardingPrincipal:
        """Authenticate only requests explicitly configured for open onboarding."""
        if request.authentication.method is not self.method:
            raise OnboardingAuthenticationError(
                "open authenticator received a different authentication method",
                code="authentication_method_mismatch",
            )
        return OnboardingPrincipal(
            authentication_method=self.method,
            trust_status="UNVERIFIED",
        )
