"""Reference private-signing-key implementation for RFC 7523 clients.

Private keys remain outside Agent Nebula. This wrapper carries only the key
object and JOSE metadata needed by the assertion builder.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_nebula_sdk.core.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class PrivateKeyJwtSigningKey:
    """Provide an asymmetric private key and its stable JOSE identifiers.

    Class responsibility
    -----------------------
    Adapts asymmetric key material to stable SDK signing interfaces.

    Standards
    ---------
    * RFC 7523
    * RFC 7521
    * RFC 7519

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    key_id: str
    algorithm: str
    private_key: object

    def __post_init__(self) -> None:
        """Reject incomplete signing-key metadata before assertion creation.

        Function responsibility
        -----------------------
        Adapts asymmetric key material to stable SDK signing interfaces.

        Standards
        ---------
        * RFC 7523
        * RFC 7521
        * RFC 7519

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
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
