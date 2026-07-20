"""Pluggable onboarding authentication strategies."""

from agent_nebula_sdk.onboarding.authentication.api_key import ApiKeyOnboardingAuthenticator
from agent_nebula_sdk.onboarding.authentication.base import OnboardingAuthenticator
from agent_nebula_sdk.onboarding.authentication.initial_access_token import (
    InitialAccessTokenOnboardingAuthenticator,
)
from agent_nebula_sdk.onboarding.authentication.mtls import MtlsOnboardingAuthenticator
from agent_nebula_sdk.onboarding.authentication.open import OpenOnboardingAuthenticator
from agent_nebula_sdk.onboarding.authentication.software_statement import (
    SoftwareStatementOnboardingAuthenticator,
)

__all__ = [
    "ApiKeyOnboardingAuthenticator",
    "InitialAccessTokenOnboardingAuthenticator",
    "MtlsOnboardingAuthenticator",
    "OnboardingAuthenticator",
    "OpenOnboardingAuthenticator",
    "SoftwareStatementOnboardingAuthenticator",
]
