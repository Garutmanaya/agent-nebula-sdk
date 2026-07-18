"""Stable SDK error hierarchy.

Protocol modules raise these errors rather than leaking library-specific
exceptions from Pydantic, ``cryptography``, or HTTP transports.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class AgentNebulaSdkError(Exception):
    """Base class for all errors intentionally exposed by the SDK."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Create a stable, machine-readable SDK error.

        Args:
            message: Human-readable explanation safe for application logs.
            code: Stable symbolic error code for adapters and API layers.
            details: Optional structured context that must not contain secrets.
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = dict(details or {})


class ConfigurationError(AgentNebulaSdkError):
    """Raised when a protocol module cannot be configured safely."""


class ProtocolValidationError(AgentNebulaSdkError):
    """Raised when protocol input violates a normative validation rule."""


class KeyValidationError(ProtocolValidationError):
    """Raised when a JWK or JWK Set is malformed or unsafe."""


class KeyResolutionError(AgentNebulaSdkError):
    """Raised when a required public key cannot be resolved."""


class DuplicateKeyIdentifierError(KeyValidationError):
    """Raised when a JWK Set contains duplicate non-empty ``kid`` values."""


class UnsupportedAlgorithmError(ProtocolValidationError):
    """Raised when a cryptographic algorithm is outside the active policy."""


class ExternalServiceError(AgentNebulaSdkError):
    """Raised when an external metadata or JWKS endpoint cannot be used."""


class UnsupportedProtocolError(AgentNebulaSdkError):
    """Raised by future protocol placeholders until their plugin is implemented."""
