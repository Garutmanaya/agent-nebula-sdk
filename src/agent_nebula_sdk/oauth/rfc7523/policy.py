"""Security policy for RFC 7523 assertion creation and validation.

RFC 7523 intentionally leaves several deployment constraints to the
authorization server. This policy makes those choices explicit, testable, and
replaceable without embedding product configuration in protocol code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from agent_nebula_sdk.core.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class Rfc7523Policy:
    """Configure the Agent Nebula private-key JWT security profile.

    Class responsibility
    -----------------------
    Holds explicit, immutable security policy used by protocol services.

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

    allowed_algorithms: frozenset[str] = frozenset({"RS256", "ES256", "EdDSA"})
    assertion_lifetime: timedelta = timedelta(minutes=5)
    maximum_assertion_lifetime: timedelta = timedelta(minutes=5)
    clock_skew: timedelta = timedelta(seconds=30)
    require_jti: bool = True
    require_iat: bool = True
    require_kid: bool = True
    maximum_assertion_bytes: int = 16_384

    def __post_init__(self) -> None:
        """Reject unsafe or contradictory policy configuration.

        Function responsibility
        -----------------------
        Holds explicit, immutable security policy used by protocol services.

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
        if not self.allowed_algorithms:
            raise ConfigurationError(
                "at least one JWT signing algorithm must be allowed",
                code="empty_algorithm_policy",
            )
        if "none" in {algorithm.lower() for algorithm in self.allowed_algorithms}:
            raise ConfigurationError(
                "the unsecured JWT algorithm is not permitted",
                code="unsecured_algorithm_rejected",
            )
        if self.assertion_lifetime <= timedelta(0):
            raise ConfigurationError(
                "assertion_lifetime must be positive",
                code="invalid_assertion_lifetime",
            )
        if self.maximum_assertion_lifetime <= timedelta(0):
            raise ConfigurationError(
                "maximum_assertion_lifetime must be positive",
                code="invalid_assertion_lifetime",
            )
        if self.assertion_lifetime > self.maximum_assertion_lifetime:
            raise ConfigurationError(
                "assertion_lifetime cannot exceed maximum_assertion_lifetime",
                code="invalid_assertion_lifetime",
            )
        if self.clock_skew < timedelta(0):
            raise ConfigurationError(
                "clock_skew cannot be negative",
                code="invalid_clock_skew",
            )
        if self.maximum_assertion_bytes < 512:
            raise ConfigurationError(
                "maximum_assertion_bytes must be at least 512",
                code="invalid_assertion_size_limit",
            )
