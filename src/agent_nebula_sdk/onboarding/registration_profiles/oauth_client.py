"""OAuth client onboarding profile delegating metadata rules to RFC 7591 models."""

from agent_nebula_sdk.oauth.rfc7591.models import RegistrationRequest
from agent_nebula_sdk.onboarding.constants import OnboardingAuthenticationMethod, RegistrationProfileType
from agent_nebula_sdk.onboarding.errors import RegistrationProfileError
from agent_nebula_sdk.onboarding.models import (
    OnboardingPrincipal,
    OnboardingRequest,
    PreparedRegistration,
)
from agent_nebula_sdk.onboarding.registration_profiles.base import RegistrationProfile


class OAuthClientRegistrationProfile(RegistrationProfile):
    """Prepare an RFC 7591 request without duplicating client metadata validation."""

    @property
    def profile_type(self) -> RegistrationProfileType:
        """Return the OAuth-client profile identifier."""
        return RegistrationProfileType.OAUTH_CLIENT

    def applies_to(self, request: OnboardingRequest) -> bool:
        """Return whether RFC 7591 client metadata is present."""
        return request.oauth_client is not None

    def prepare(
        self,
        request: OnboardingRequest,
        principal: OnboardingPrincipal,
    ) -> PreparedRegistration:
        """Build the existing RFC 7591 request consumed by a product transaction adapter."""
        del principal
        if request.oauth_client is None:
            raise RegistrationProfileError(
                "OAuth client registration profile is missing",
                code="missing_oauth_client_profile",
            )
        initial_access_token = None
        if request.authentication.method is OnboardingAuthenticationMethod.INITIAL_ACCESS_TOKEN:
            initial_access_token = request.authentication.credential
        payload = RegistrationRequest(
            metadata=request.oauth_client.metadata,
            initial_access_token=initial_access_token,
            request_headers=request.context.request_headers,
            remote_address=request.context.remote_address,
        )
        return PreparedRegistration(profile_type=self.profile_type, payload=payload)
