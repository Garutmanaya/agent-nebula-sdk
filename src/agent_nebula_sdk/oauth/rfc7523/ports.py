"""Infrastructure ports required by the RFC 7523 protocol module.

The SDK owns protocol processing but no product database. Agent Nebula supplies
PostgreSQL or Redis adapters, while SDK tests can use deterministic in-memory
implementations of these ports.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk


class ClientSigningKey(Protocol):
    """Private signing-key abstraction used by assertion builders.

    Class responsibility
    -----------------------
    Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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

    @property
    def key_id(self) -> str:
        """Return the JOSE ``kid`` placed in the assertion header.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...

    @property
    def algorithm(self) -> str:
        """Return the configured asymmetric JWS algorithm name.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...

    @property
    def private_key(self) -> object:
        """Return a private-key object accepted by the configured JOSE library.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...


class RegisteredClient(Protocol):
    """Minimal registered-client record needed for client authentication.

    Class responsibility
    -----------------------
    Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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

    @property
    def client_id(self) -> str:
        """Return the OAuth client identifier.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...

    @property
    def is_active(self) -> bool:
        """Return whether authentication is currently permitted.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...

    @property
    def token_endpoint_auth_method(self) -> str:
        """Return the registered OAuth token-endpoint authentication method.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...

    @property
    def metadata(self) -> dict[str, Any]:
        """Return non-secret metadata propagated into authentication context.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...


class RegisteredClientStore(Protocol):
    """Resolve registered clients without coupling the SDK to persistence.

    Class responsibility
    -----------------------
    Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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

    def get_client(self, client_id: str) -> RegisteredClient | None:
        """Return a registered client or ``None`` when it does not exist.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...


class ClientPublicKeyResolver(Protocol):
    """Resolve one registered public key for a client assertion.

    Class responsibility
    -----------------------
    Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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

    def resolve_client_key(
        self,
        *,
        client_id: str,
        key_id: str,
        algorithm: str,
    ) -> SupportedPublicJwk:
        """Return the validated public JWK matching client, ``kid``, and algorithm.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...


class AssertionReplayStore(Protocol):
    """Atomically consume assertion identifiers to prevent replay.

    Class responsibility
    -----------------------
    Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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

    def consume(
        self,
        *,
        namespace: str,
        subject: str,
        assertion_id: str,
        expires_at: datetime,
    ) -> bool:
        """Return ``True`` only for the first valid use of an assertion identifier.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...


class AuthorizationGrantKeyResolver(Protocol):
    """Resolve a public key for an RFC 7523 authorization-grant issuer.

    Class responsibility
    -----------------------
    Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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

    def resolve_issuer_key(
        self,
        *,
        issuer: str,
        key_id: str,
        algorithm: str,
    ) -> SupportedPublicJwk:
        """Return the public JWK registered for an assertion issuer.

        Function responsibility
        -----------------------
        Defines product-neutral interfaces implemented by Agent Nebula or Agent Genesis.

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
        ...
