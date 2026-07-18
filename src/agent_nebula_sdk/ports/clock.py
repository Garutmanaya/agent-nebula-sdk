"""Injectable clock abstraction for deterministic protocol validation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Return the current timezone-aware UTC instant.

    Class responsibility
    -----------------------
    Abstracts current time so temporal validation is deterministic and testable.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def now(self) -> datetime:
        """Return the current UTC instant.

        Function responsibility
        -----------------------
        Abstracts current time so temporal validation is deterministic and testable.

        Standards
        ---------
        * Internal SDK contract

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """


class SystemClock:
    """Production clock implementation backed by the operating system.

    Class responsibility
    -----------------------
    Abstracts current time so temporal validation is deterministic and testable.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def now(self) -> datetime:
        """Return the current timezone-aware UTC instant.

        Function responsibility
        -----------------------
        Abstracts current time so temporal validation is deterministic and testable.

        Standards
        ---------
        * Internal SDK contract

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        return datetime.now(UTC)
