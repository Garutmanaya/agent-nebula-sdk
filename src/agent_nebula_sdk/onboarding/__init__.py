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
    AgentProfileResult,
    AgentRegistrationInput,
    OAuthClientProfileResult,
    OAuthClientRegistrationInput,
    OnboardingAuthenticationInput,
    OnboardingCommitResult,
    OnboardingPrincipal,
    OnboardingRequest,
    OnboardingRequestContext,
    OnboardingResult,
    PreparedOnboardingRegistration,
    PreparedRegistration,
    ProtectedResourceProfileResult,
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
    "AgentProfileResult",
    "AgentRegistrationInput",
    "AgentRegistrationProfile",
    "AgentRole",
    "ApiKeyOnboardingAuthenticator",
    "InitialAccessTokenOnboardingAuthenticator",
    "MtlsOnboardingAuthenticator",
    "OAuthClientProfileResult",
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
    "ProtectedResourceProfileResult",
    "ProtectedResourceRegistrationInput",
    "ProtectedResourceRegistrationProfile",
    "RegistrationProfile",
    "RegistrationProfileType",
    "SoftwareStatementOnboardingAuthenticator",
]
