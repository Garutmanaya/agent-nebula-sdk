"""Public entry point for secure, pluggable, multi-profile agent onboarding."""

from agent_nebula_sdk.onboarding.authentication import (
    ApiKeyOnboardingAuthenticator,
    InitialAccessTokenOnboardingAuthenticator,
    MtlsOnboardingAuthenticator,
    OnboardingAuthenticator,
    OpenOnboardingAuthenticator,
    SoftwareStatementOnboardingAuthenticator,
)
from agent_nebula_sdk.onboarding.constants import (
    AgentRole,
    OnboardingAuthenticationMethod,
    RegistrationProfileType,
)
from agent_nebula_sdk.onboarding.models import (
    AgentRegistrationInput,
    OAuthClientRegistrationInput,
    OnboardingAuthenticationInput,
    OnboardingCommitResult,
    OnboardingPrincipal,
    OnboardingRequest,
    OnboardingRequestContext,
    OnboardingResult,
    PreparedOnboardingRegistration,
    PreparedRegistration,
    ProtectedResourceRegistrationInput,
)
from agent_nebula_sdk.onboarding.plugin import OnboardingRuntimePlugin
from agent_nebula_sdk.onboarding.registration_profiles import (
    AgentRegistrationProfile,
    OAuthClientRegistrationProfile,
    ProtectedResourceRegistrationProfile,
    RegistrationProfile,
)
from agent_nebula_sdk.onboarding.registry import OnboardingComponentRegistry
from agent_nebula_sdk.onboarding.service import OnboardingService

__all__ = [
    "AgentRegistrationInput",
    "AgentRegistrationProfile",
    "AgentRole",
    "ApiKeyOnboardingAuthenticator",
    "InitialAccessTokenOnboardingAuthenticator",
    "MtlsOnboardingAuthenticator",
    "OAuthClientRegistrationInput",
    "OAuthClientRegistrationProfile",
    "OnboardingAuthenticationInput",
    "OnboardingAuthenticationMethod",
    "OnboardingAuthenticator",
    "OnboardingCommitResult",
    "OnboardingComponentRegistry",
    "OnboardingPrincipal",
    "OnboardingRequest",
    "OnboardingRequestContext",
    "OnboardingResult",
    "OnboardingRuntimePlugin",
    "OnboardingService",
    "OpenOnboardingAuthenticator",
    "PreparedOnboardingRegistration",
    "PreparedRegistration",
    "ProtectedResourceRegistrationInput",
    "ProtectedResourceRegistrationProfile",
    "RegistrationProfile",
    "RegistrationProfileType",
    "SoftwareStatementOnboardingAuthenticator",
]
