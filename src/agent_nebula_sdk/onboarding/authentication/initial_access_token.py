"""Controlled onboarding using a product-issued initial access token."""

from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.constants import OnboardingAuthenticationMethod
from agent_nebula_sdk.onboarding.errors import OnboardingAuthenticationError
from agent_nebula_sdk.onboarding.models import OnboardingPrincipal, OnboardingRequest
from agent_nebula_sdk.onboarding.ports import InitialAccessTokenVerifier


class InitialAccessTokenOnboardingAuthenticator(OnboardingAuthenticator):
    """Delegate atomic verification and consumption of an initial access token."""

    def __init__(self, verifier: InitialAccessTokenVerifier) -> None:
        """Configure the product adapter that owns token lifecycle and persistence."""
        self._verifier = verifier

    @property
    def method(self) -> OnboardingAuthenticationMethod:
        """Return the initial-access-token method identifier."""
        return OnboardingAuthenticationMethod.INITIAL_ACCESS_TOKEN

    def authenticate(self, request: OnboardingRequest) -> OnboardingPrincipal:
        """Consume the supplied token before any profile or network processing."""
        credential = request.authentication.credential
        if request.authentication.method is not self.method or credential is None:
            raise OnboardingAuthenticationError(
                "initial access token is missing or misrouted",
                code="invalid_initial_access_token_authentication",
            )
        principal = self._verifier.verify_and_consume(credential)
        return principal.model_copy(update={"authentication_method": self.method})
