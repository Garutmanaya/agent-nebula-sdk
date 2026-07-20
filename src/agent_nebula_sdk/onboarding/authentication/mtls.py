"""Explicit placeholder for future certificate-authenticated onboarding."""

from agent_nebula_sdk.core.errors import UnsupportedProtocolError
from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.constants import OnboardingAuthenticationMethod
from agent_nebula_sdk.onboarding.models import OnboardingPrincipal, OnboardingRequest


class MtlsOnboardingAuthenticator(OnboardingAuthenticator):
    """Fail explicitly until RFC 8705 and certificate trust services are implemented."""

    @property
    def method(self) -> OnboardingAuthenticationMethod:
        """Return the mTLS method identifier reserved by the onboarding API."""
        return OnboardingAuthenticationMethod.MTLS

    def authenticate(self, request: OnboardingRequest) -> OnboardingPrincipal:
        """Reject use rather than silently providing incomplete certificate validation."""
        del request
        raise UnsupportedProtocolError(
            "mTLS onboarding is unavailable until RFC 8705 is implemented",
            code="mtls_onboarding_not_implemented",
        )
