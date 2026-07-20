"""Software-statement onboarding using the existing RFC 7591 verifier contract."""

from agent_nebula_sdk.oauth.rfc7591.ports import SoftwareStatementVerifier
from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.constants import OnboardingAuthenticationMethod
from agent_nebula_sdk.onboarding.errors import OnboardingAuthenticationError
from agent_nebula_sdk.onboarding.models import OnboardingPrincipal, OnboardingRequest


class SoftwareStatementOnboardingAuthenticator(OnboardingAuthenticator):
    """Establish publisher trust from a verified RFC 7591 software statement."""

    def __init__(self, verifier: SoftwareStatementVerifier) -> None:
        """Configure the existing RFC 7591 software-statement verifier port."""
        self._verifier = verifier

    @property
    def method(self) -> OnboardingAuthenticationMethod:
        """Return the software-statement method identifier."""
        return OnboardingAuthenticationMethod.SOFTWARE_STATEMENT

    def authenticate(self, request: OnboardingRequest) -> OnboardingPrincipal:
        """Verify the signed statement and expose trusted claims to profile handlers."""
        statement = request.authentication.credential
        if request.authentication.method is not self.method or statement is None:
            raise OnboardingAuthenticationError(
                "software statement is missing or misrouted",
                code="invalid_software_statement_authentication",
            )
        try:
            claims = self._verifier.verify(statement)
        except Exception as exc:
            raise OnboardingAuthenticationError(
                "software statement verification failed",
                code="invalid_software_statement",
            ) from exc
        subject = claims.get("sub") or claims.get("software_id") or claims.get("iss")
        return OnboardingPrincipal(
            subject=str(subject) if subject is not None else None,
            authentication_method=self.method,
            trust_status="VERIFIED_SOFTWARE_STATEMENT",
            claims=claims,
        )
