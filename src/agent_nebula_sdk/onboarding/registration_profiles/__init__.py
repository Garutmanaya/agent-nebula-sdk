"""Pluggable registration profiles composed by the onboarding service."""

from agent_nebula_sdk.onboarding.registration_profiles.agent import AgentRegistrationProfile
from agent_nebula_sdk.onboarding.registration_profiles.base import RegistrationProfile
from agent_nebula_sdk.onboarding.registration_profiles.oauth_client import (
    OAuthClientRegistrationProfile,
)
from agent_nebula_sdk.onboarding.registration_profiles.protected_resource import (
    ProtectedResourceRegistrationProfile,
)

__all__ = [
    "AgentRegistrationProfile",
    "OAuthClientRegistrationProfile",
    "ProtectedResourceRegistrationProfile",
    "RegistrationProfile",
]
