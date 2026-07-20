"""Protected-resource onboarding using RFC 9728 and RFC 8707 semantics."""

from agent_nebula_sdk.onboarding.constants import RegistrationProfileType
from agent_nebula_sdk.onboarding.errors import RegistrationProfileError
from agent_nebula_sdk.onboarding.models import (
    OnboardingPrincipal,
    OnboardingRequest,
    PreparedRegistration,
)
from agent_nebula_sdk.onboarding.registration_profiles.base import RegistrationProfile


class ProtectedResourceRegistrationProfile(RegistrationProfile):
    """Prepare RFC 9728 metadata for later RFC 8707 audience resolution."""

    @property
    def profile_type(self) -> RegistrationProfileType:
        """Return the protected-resource profile identifier."""
        return RegistrationProfileType.PROTECTED_RESOURCE

    def applies_to(self, request: OnboardingRequest) -> bool:
        """Return whether protected-resource metadata is present."""
        return request.protected_resource is not None

    def prepare(
        self,
        request: OnboardingRequest,
        principal: OnboardingPrincipal,
    ) -> PreparedRegistration:
        """Validate self-consistency through the existing RFC 9728 metadata model."""
        del principal
        resource = request.protected_resource
        if resource is None:
            raise RegistrationProfileError(
                "protected-resource registration profile is missing",
                code="missing_protected_resource_profile",
            )
        resource.metadata.validate_for_requested_resource(resource.metadata.resource)
        return PreparedRegistration(profile_type=self.profile_type, payload=resource)
