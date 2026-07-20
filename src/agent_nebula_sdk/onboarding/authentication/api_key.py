"""API-key onboarding adapter that delegates all credential handling to products."""

from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.constants import OnboardingAuthenticationMethod
from agent_nebula_sdk.onboarding.errors import OnboardingAuthenticationError
from agent_nebula_sdk.onboarding.models import OnboardingPrincipal, OnboardingRequest
from agent_nebula_sdk.onboarding.ports import ApiKeyVerifier


class ApiKeyOnboardingAuthenticator(OnboardingAuthenticator):
    """Authenticate opaque API keys through an injected product verifier."""

    def __init__(self, verifier: ApiKeyVerifier) -> None:
        """Configure the product-owned API-key verification adapter."""
        self._verifier = verifier

    @property
    def method(self) -> OnboardingAuthenticationMethod:
        """Return the API-key method identifier."""
        return OnboardingAuthenticationMethod.API_KEY

    def authenticate(self, request: OnboardingRequest) -> OnboardingPrincipal:
        """Verify the supplied key exactly once and normalize the resulting principal."""
        credential = request.authentication.credential
        if request.authentication.method is not self.method or credential is None:
            raise OnboardingAuthenticationError(
                "API-key onboarding credential is missing or misrouted",
                code="invalid_api_key_authentication",
            )
        principal = self._verifier.verify(credential)
        return principal.model_copy(update={"authentication_method": self.method})
