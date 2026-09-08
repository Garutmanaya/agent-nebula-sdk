"""Stable identifiers for the protocol-neutral onboarding orchestration API."""

from enum import StrEnum


class OnboardingAuthenticationMethod(StrEnum):
    """Identify the mechanism used to authenticate an onboarding request."""

    OPEN = "OPEN"
    API_KEY = "API_KEY"
    INITIAL_ACCESS_TOKEN = "INITIAL_ACCESS_TOKEN"
    SOFTWARE_STATEMENT = "SOFTWARE_STATEMENT"
    MTLS = "MTLS"


class RegistrationProfileType(StrEnum):
    """Identify one independently processed onboarding registration profile."""

    AGENT = "AGENT"
    OAUTH_CLIENT = "OAUTH_CLIENT"
    PROTECTED_RESOURCE = "PROTECTED_RESOURCE"


class AgentRole(StrEnum):
    """Describe protocol roles that one dynamically onboarded agent may hold."""

    A2A_PROVIDER = "A2A_PROVIDER"
    A2A_CALLER = "A2A_CALLER"
    OAUTH_CLIENT = "OAUTH_CLIENT"
    OAUTH_PROTECTED_RESOURCE = "OAUTH_PROTECTED_RESOURCE"
    MCP_CLIENT = "MCP_CLIENT"
    MCP_SERVER = "MCP_SERVER"
