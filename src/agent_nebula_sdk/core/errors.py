"""Stable SDK error hierarchy.

Protocol modules raise these errors rather than leaking library-specific
exceptions from Pydantic, ``cryptography``, or HTTP transports.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class AgentNebulaSdkError(Exception):
    """Base class for all errors intentionally exposed by the SDK.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Create a stable, machine-readable SDK error.

            Function responsibility
            -----------------------
            Defines stable SDK exceptions that callers may handle without depending on
        third-party libraries.

            Standards
            ---------
            * Internal SDK contract

            Operational notes
            -----------------
            The function does not retain mutable protocol state unless explicitly documented.
            Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = dict(details or {})


class ConfigurationError(AgentNebulaSdkError):
    """Raised when a protocol module cannot be configured safely.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class ProtocolValidationError(AgentNebulaSdkError):
    """Raised when protocol input violates a normative validation rule.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class KeyValidationError(ProtocolValidationError):
    """Raised when a JWK or JWK Set is malformed or unsafe.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class KeyResolutionError(AgentNebulaSdkError):
    """Raised when a required public key cannot be resolved.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class DuplicateKeyIdentifierError(KeyValidationError):
    """Raised when a JWK Set contains duplicate non-empty ``kid`` values.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class UnsupportedAlgorithmError(ProtocolValidationError):
    """Raised when a cryptographic algorithm is outside the active policy.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class ExternalServiceError(AgentNebulaSdkError):
    """Raised when an external metadata or JWKS endpoint cannot be used.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class UnsupportedProtocolError(AgentNebulaSdkError):
    """Raised by future protocol placeholders until their plugin is implemented.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class ClientAuthenticationError(ProtocolValidationError):
    """Raised when OAuth client authentication cannot be established.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class AuthorizationGrantError(ProtocolValidationError):
    """Raised when an assertion authorization grant is invalid.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """


class ReplayDetectedError(ProtocolValidationError):
    """Raised when a one-time assertion or proof identifier is reused.

    Class responsibility
    -----------------------
    Defines stable SDK exceptions that callers may handle without depending on
    third-party libraries.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """
