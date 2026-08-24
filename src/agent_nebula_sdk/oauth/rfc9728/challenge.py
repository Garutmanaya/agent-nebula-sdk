"""WWW-Authenticate challenge creation and parsing for protected resources.

RFC 9728 Section 5.1 defines the ``resource_metadata`` authentication
parameter. MCP requires clients to understand this challenge when a protected
server returns HTTP 401.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

from agent_nebula_sdk.core.errors import ProtocolValidationError

_PARAMETER_PATTERN = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)=(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))')


class OAuthChallenge(BaseModel):
    """Represent the OAuth authentication information from WWW-Authenticate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: str
    resource_metadata: str | None = None
    scope: tuple[str, ...] = ()
    error: str | None = None
    error_description: str | None = None


class OAuthChallengeCodec:
    """Encode and parse RFC 6750/RFC 9728 authentication challenges."""

    def build(
        self,
        *,
        resource_metadata: str,
        scope: tuple[str, ...] = (),
        error: str | None = None,
        error_description: str | None = None,
        scheme: str = "DPoP",
    ) -> str:
        """Build a safely quoted authentication challenge for a 401 response."""
        parameters = [f'resource_metadata="{self._escape(resource_metadata)}"']
        if scope:
            parameters.append(f'scope="{self._escape(" ".join(scope))}"')
        if error is not None:
            parameters.append(f'error="{self._escape(error)}"')
        if error_description is not None:
            parameters.append(f'error_description="{self._escape(error_description)}"')
        return f"{scheme} " + ", ".join(parameters)

    def parse(self, header_value: str) -> OAuthChallenge:
        """Parse one Bearer or DPoP challenge and retain supported parameters."""
        scheme, separator, parameters_text = header_value.strip().partition(" ")
        if not separator or scheme.lower() not in {"bearer", "dpop"}:
            raise ProtocolValidationError(
                "unsupported WWW-Authenticate challenge",
                code="invalid_authentication_challenge",
            )
        parameters: dict[str, str] = {}
        for match in _PARAMETER_PATTERN.finditer(parameters_text):
            raw_value = match.group(2) if match.group(2) is not None else match.group(3)
            parameters[match.group(1).lower()] = self._unescape(raw_value or "")
        return OAuthChallenge(
            scheme=scheme,
            resource_metadata=parameters.get("resource_metadata"),
            scope=tuple(parameters.get("scope", "").split()),
            error=parameters.get("error"),
            error_description=parameters.get("error_description"),
        )

    @staticmethod
    def _escape(value: str) -> str:
        """Escape backslash and double quote for an HTTP quoted-string."""
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _unescape(value: str) -> str:
        """Unescape a conservative HTTP quoted-string representation."""
        return value.replace('\\"', '"').replace("\\\\", "\\")
