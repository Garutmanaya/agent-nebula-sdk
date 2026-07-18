"""Pluggable registration authorization policies.

RFC 7591 permits open registration and protected registration using an initial
access token. These policies implement both modes without embedding product
business rules in the protocol service.
"""

from __future__ import annotations

from collections.abc import Callable

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc7591.models import ClientMetadata, RegistrationRequest


class OpenRegistrationPolicy:
    """Allow public registration and assign an unverified trust status.

    Open registration improves adoption but does not establish organizational
    trust. Consumers should use the returned trust status as an input to later
    scoring and local provider authorization.
    """

    def __init__(
        self,
        *,
        extension_validator: Callable[[ClientMetadata], None] | None = None,
        allowed_extension_names: frozenset[str] = frozenset(),
    ) -> None:
        """Create an open policy with an optional extension validator."""
        self._extension_validator = extension_validator
        self._allowed_extension_names = allowed_extension_names

    def authorize(self, request: RegistrationRequest) -> None:
        """Allow the request without an initial access token."""
        del request

    def registration_method(self, request: RegistrationRequest) -> str:
        """Return the auditable method assigned to public registration."""
        del request
        return "open_rfc7591"

    def trust_status(self, request: RegistrationRequest) -> str:
        """Return the initial trust status for public registrations."""
        del request
        return "UNVERIFIED"

    def validate_extensions(self, metadata: ClientMetadata) -> None:
        """Delegate product extension validation when configured."""
        if self._extension_validator is not None:
            self._extension_validator(metadata)

    def allowed_extension_names(self) -> frozenset[str]:
        """Return extension names understood by the open-registration profile."""
        return self._allowed_extension_names


class InitialAccessTokenRegistrationPolicy:
    """Require a valid initial access token for controlled registration.

    RFC 7591 Section 3 permits the registration endpoint to accept an OAuth
    access token. Token verification and one-time use are delegated through an
    injected callback so Agent Nebula can use its existing token subsystem.
    """

    def __init__(
        self,
        *,
        token_validator: Callable[[str], bool],
        extension_validator: Callable[[ClientMetadata], None] | None = None,
        allowed_extension_names: frozenset[str] = frozenset(),
        trust_status: str = "VERIFIED_ONBOARDING",
    ) -> None:
        """Configure controlled registration token verification and trust output."""
        self._token_validator = token_validator
        self._extension_validator = extension_validator
        self._allowed_extension_names = allowed_extension_names
        self._trust_status = trust_status

    def authorize(self, request: RegistrationRequest) -> None:
        """Require and validate the initial access token."""
        token = request.initial_access_token
        if token is None or not self._token_validator(token):
            raise ProtocolValidationError(
                "registration requires a valid initial access token",
                code="invalid_initial_access_token",
            )

    def registration_method(self, request: RegistrationRequest) -> str:
        """Return the controlled registration audit label."""
        del request
        return "controlled_rfc7591"

    def trust_status(self, request: RegistrationRequest) -> str:
        """Return the configured controlled-registration trust status."""
        del request
        return self._trust_status

    def validate_extensions(self, metadata: ClientMetadata) -> None:
        """Delegate product extension validation when configured."""
        if self._extension_validator is not None:
            self._extension_validator(metadata)

    def allowed_extension_names(self) -> frozenset[str]:
        """Return extension names understood by controlled registration."""
        return self._allowed_extension_names
