"""HTTP transport port used by protocol clients and resolvers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Transport-neutral HTTP response required by SDK protocol modules.

    Class responsibility
    -----------------------
    Defines transport-neutral HTTP contracts used by protocol modules.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    status_code: int
    headers: dict[str, str]
    body: bytes


class HttpTransport(Protocol):
    """Minimal outbound HTTP contract.

    Class responsibility
    -----------------------
    Defines transport-neutral HTTP contracts used by protocol modules.

    Standards
    ---------
    * Internal SDK contract

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Issue an HTTPS GET request and return a transport-neutral response.

        Function responsibility
        -----------------------
        Defines transport-neutral HTTP contracts used by protocol modules.

        Standards
        ---------
        * Internal SDK contract

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResponse:
        """Issue an HTTPS POST request and return a transport-neutral response.

        The SDK passes already serialized protocol bodies so transport adapters
        do not need to understand OAuth, JOSE, or MCP payload semantics.
        """
        ...
    def put(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResponse:
        """Issue an HTTPS PUT request with a pre-serialized protocol body."""
        ...

    def delete(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Issue an HTTPS DELETE request and return a transport-neutral response."""
        ...

