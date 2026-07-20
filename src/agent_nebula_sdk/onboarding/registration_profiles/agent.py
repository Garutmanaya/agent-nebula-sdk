"""Protocol-neutral Agent identity onboarding profile."""

from agent_nebula_sdk.onboarding.constants import RegistrationProfileType
from agent_nebula_sdk.onboarding.errors import RegistrationProfileError
from agent_nebula_sdk.onboarding.models import (
    OnboardingPrincipal,
    OnboardingRequest,
    PreparedRegistration,
)
from agent_nebula_sdk.onboarding.registration_profiles.base import RegistrationProfile


class AgentRegistrationProfile(RegistrationProfile):
    """Prepare Agent identity metadata while leaving discovery persistence to products."""

    @property
    def profile_type(self) -> RegistrationProfileType:
        """Return the Agent profile identifier."""
        return RegistrationProfileType.AGENT

    def applies_to(self, request: OnboardingRequest) -> bool:
        """Return whether Agent identity metadata is present."""
        return request.agent is not None

    def prepare(
        self,
        request: OnboardingRequest,
        principal: OnboardingPrincipal,
    ) -> PreparedRegistration:
        """Return validated Agent metadata without fetching or storing the Agent Card."""
        del principal
        if request.agent is None:
            raise RegistrationProfileError(
                "agent registration profile is missing",
                code="missing_agent_profile",
            )
        return PreparedRegistration(profile_type=self.profile_type, payload=request.agent)
