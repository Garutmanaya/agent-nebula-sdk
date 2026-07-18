"""Authorization-server service for RFC 7523 client authentication.

This service composes client lookup, public-key resolution, JWT validation, and
atomic replay protection. Product code invokes this class instead of directly
handling JWTs or persistence records.
"""

from __future__ import annotations

from datetime import UTC, datetime

from agent_nebula_sdk.core.errors import (
    KeyResolutionError,
    ProtocolValidationError,
    ReplayDetectedError,
)
from agent_nebula_sdk.oauth.rfc7523.models import (
    AuthenticatedClient,
    ClientAuthenticationRequest,
)
from agent_nebula_sdk.oauth.rfc7523.ports import (
    AssertionReplayStore,
    ClientPublicKeyResolver,
    RegisteredClientStore,
)
from agent_nebula_sdk.oauth.rfc7523.validator import JwtAssertionValidator


class PrivateKeyJwtAuthenticator:
    """Authenticate registered OAuth clients using ``private_key_jwt``.

    Class responsibility
    -----------------------
    Coordinates client authentication while delegating storage and key lookup through ports.

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

    def __init__(
        self,
        *,
        clients: RegisteredClientStore,
        keys: ClientPublicKeyResolver,
        replay_store: AssertionReplayStore,
        validator: JwtAssertionValidator,
        accepted_audiences: tuple[str, ...],
    ) -> None:
        """Create the authorization-server client-authentication service.

        Function responsibility
        -----------------------
        Coordinates client authentication while delegating storage and key lookup through ports.

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
        if not accepted_audiences:
            raise ValueError("accepted_audiences must not be empty")
        self._clients = clients
        self._keys = keys
        self._replay_store = replay_store
        self._validator = validator
        self._accepted_audiences = accepted_audiences

    def authenticate(self, request: ClientAuthenticationRequest) -> AuthenticatedClient:
        """Validate a request and return a stable authenticated-client context.

        Function responsibility
        -----------------------
        Coordinates client authentication while delegating storage and key lookup through ports.

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
        # The issuer is read before signature verification only to locate the registered
        # client record. No unverified claim is accepted as authenticated identity.
        untrusted_claims = self._validator.decode_unverified_claims(request.client_assertion)
        untrusted_client_id = untrusted_claims.get("iss")
        if not isinstance(untrusted_client_id, str) or not untrusted_client_id:
            raise ProtocolValidationError(
                "client assertion requires a non-empty iss claim",
                code="missing_client_identifier",
            )
        if request.client_id is not None and request.client_id != untrusted_client_id:
            raise ProtocolValidationError(
                "client_id does not match assertion issuer",
                code="client_identifier_mismatch",
            )
        # Resolve the product-owned client record through the SDK port. The SDK never
        # assumes a database schema or persistence technology.
        client = self._clients.get_client(untrusted_client_id)
        if client is None:
            raise ProtocolValidationError(
                "OAuth client is not registered",
                code="unknown_client",
            )
        if not client.is_active:
            raise ProtocolValidationError(
                "OAuth client is disabled",
                code="inactive_client",
            )
        if client.token_endpoint_auth_method != "private_key_jwt":
            raise ProtocolValidationError(
                "OAuth client is not registered for private_key_jwt",
                code="client_authentication_method_mismatch",
            )
        # RFC 7523 relies on JOSE key selection. ``kid`` and ``alg`` are inspected
        # only to resolve the candidate public key; signature verification follows.
        key_id, algorithm = self._validator.read_unverified_header(request.client_assertion)
        try:
            public_key = self._keys.resolve_client_key(
                client_id=client.client_id,
                key_id=key_id,
                algorithm=algorithm,
            )
        except KeyResolutionError:
            raise
        # The validator performs cryptographic and claim validation before the replay
        # identifier is consumed. This avoids storing identifiers from invalid JWTs.
        verified = self._validator.verify_client_assertion(
            assertion=request.client_assertion,
            public_jwk=public_key,
            accepted_audiences=self._accepted_audiences,
        )
        claims = verified.claims
        if claims["iss"] != client.client_id or claims["sub"] != client.client_id:
            raise ProtocolValidationError(
                "assertion identity does not match the registered client",
                code="client_identifier_mismatch",
            )
        issued_at = datetime.fromtimestamp(int(claims["iat"]), tz=UTC)
        expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=UTC)
        consumed = self._replay_store.consume(
            namespace="rfc7523:client-authentication",
            subject=client.client_id,
            assertion_id=str(claims["jti"]),
            expires_at=expires_at,
        )
        if not consumed:
            raise ReplayDetectedError(
                "client assertion has already been used",
                code="assertion_replay_detected",
            )
        return AuthenticatedClient(
            client_id=client.client_id,
            key_id=verified.key_id,
            algorithm=verified.algorithm,
            assertion_id=str(claims["jti"]),
            issued_at=issued_at,
            expires_at=expires_at,
            metadata=dict(client.metadata),
        )
