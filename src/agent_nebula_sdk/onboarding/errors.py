"""Stable onboarding errors exposed independently from product frameworks."""

from agent_nebula_sdk.core.errors import AgentNebulaSdkError, ProtocolValidationError


class OnboardingAuthenticationError(ProtocolValidationError):
    """Raised when onboarding request authentication cannot be established."""


class RegistrationProfileError(ProtocolValidationError):
    """Raised when a declared registration profile is invalid or unsupported."""


class OnboardingCommitError(AgentNebulaSdkError):
    """Raised when the product-owned atomic onboarding transaction fails."""
