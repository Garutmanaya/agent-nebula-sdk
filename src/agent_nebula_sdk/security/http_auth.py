"""Generic HTTP Authorization-scheme authentication."""
from __future__ import annotations

import base64
from typing import Protocol

from agent_nebula_sdk.core.errors import ProtocolValidationError

from .models import AuthenticatedIdentity


class HttpCredentialVerifier(Protocol):
    """Product-owned verifier for one HTTP authentication scheme."""

    def verify(self, credential: str) -> AuthenticatedIdentity:
        """Verify the opaque credential and return a trusted identity."""
        ...


class HttpAuthAuthenticator:
    """Parse an Authorization header and delegate credential verification."""

    def __init__(self, *, scheme: str, verifier: HttpCredentialVerifier) -> None:
        """Configure one HTTP authentication scheme and verifier."""
        if not scheme.strip():
            raise ValueError("scheme must not be empty")
        self._scheme = scheme
        self._verifier = verifier

    @property
    def scheme(self) -> str:
        """Return the configured HTTP authentication scheme."""
        return self._scheme

    def authenticate(self, authorization: str) -> AuthenticatedIdentity:
        """Parse and verify one Authorization header value."""
        prefix, sep, credential = authorization.partition(" ")
        if not sep or prefix.lower() != self._scheme.lower() or not credential.strip():
            raise ProtocolValidationError(
                "HTTP authorization credential is missing or has the wrong scheme",
                code="invalid_http_authentication",
            )
        return self._verifier.verify(credential.strip())


class BasicCredentialDecoder:
    """Strict RFC 7617 decoder; password verification remains product-owned."""

    @staticmethod
    def decode(credential: str) -> tuple[str, str]:
        """Decode a Basic credential into username and password."""
        try:
            decoded = base64.b64decode(credential, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProtocolValidationError(
                "Basic authentication credential is malformed",
                code="invalid_http_authentication",
            ) from exc
        username, sep, password = decoded.partition(":")
        if not sep or not username:
            raise ProtocolValidationError(
                "Basic authentication credential is malformed",
                code="invalid_http_authentication",
            )
        return username, password
