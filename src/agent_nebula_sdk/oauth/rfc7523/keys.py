"""Reference private-signing-key implementation for RFC 7523 clients.

Private keys remain outside Agent Nebula. This wrapper carries only the key
object and JOSE metadata needed by the assertion builder.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_nebula_sdk.core.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class PrivateKeyJwtSigningKey:
    """Provide an asymmetric private key and its stable JOSE identifiers."""

    key_id: str
    algorithm: str
    private_key: object

    def __post_init__(self) -> None:
        """Reject incomplete signing-key metadata before assertion creation."""
        if not self.key_id.strip():
            raise ConfigurationError(
                "private-key JWT signing key requires a non-empty key_id",
                code="missing_signing_key_id",
            )
        if not self.algorithm.strip():
            raise ConfigurationError(
                "private-key JWT signing key requires an algorithm",
                code="missing_signing_algorithm",
            )
