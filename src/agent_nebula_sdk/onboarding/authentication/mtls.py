"""Certificate-authenticated onboarding backed by the generic mTLS trust service."""

from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.constants import OnboardingAuthenticationMethod
from agent_nebula_sdk.onboarding.errors import OnboardingAuthenticationError
from agent_nebula_sdk.onboarding.models import OnboardingPrincipal, OnboardingRequest
from agent_nebula_sdk.security import MtlsClientCertificateAuthenticator


class MtlsOnboardingAuthenticator(OnboardingAuthenticator):
    """Authenticate onboarding callers from the transport peer certificate."""

    def __init__(self, authenticator: MtlsClientCertificateAuthenticator) -> None:
        """Configure the shared X.509 trust validator."""
        self._authenticator = authenticator

    @property
    def method(self) -> OnboardingAuthenticationMethod:
        """Return the mTLS onboarding authentication method."""
        return OnboardingAuthenticationMethod.MTLS

    def authenticate(self, request: OnboardingRequest) -> OnboardingPrincipal:
        """Authenticate the transport peer certificate and normalize the principal."""
        certificate = request.context.peer_certificate
        if request.authentication.method is not self.method or certificate is None:
            raise OnboardingAuthenticationError(
                "mTLS peer certificate is missing or misrouted",
                code="invalid_mtls_authentication",
            )
        identity = self._authenticator.authenticate(certificate)
        return OnboardingPrincipal(
            subject=identity.subject,
            authentication_method=self.method,
            trust_status="verified",
            claims={"certificate_subject": identity.subject},
        )
