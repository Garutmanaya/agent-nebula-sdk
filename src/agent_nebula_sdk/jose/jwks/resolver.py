"""Remote RFC 7517 JWK Set resolver with bounded caching and refresh."""

from __future__ import annotations

import json
from datetime import timedelta

from pydantic import ValidationError

from agent_nebula_sdk.core.errors import ExternalServiceError, KeyResolutionError
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk
from agent_nebula_sdk.jose.jwks.cache import JwksCache
from agent_nebula_sdk.jose.jwks.models import JwkSet
from agent_nebula_sdk.jose.jwks.uri_policy import JwksUriPolicy
from agent_nebula_sdk.ports.http import HttpTransport


class RemoteJwksResolver:
    """Resolve keys from an HTTPS JWK Set endpoint.

    Class responsibility
    -----------------------
    Resolves protocol data through an injected source while enforcing security policy.

    Standards
    ---------
    * RFC 7517
    * RFC 7517

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def __init__(
        self,
        *,
        transport: HttpTransport,
        cache: JwksCache,
        uri_policy: JwksUriPolicy,
        default_ttl: timedelta = timedelta(minutes=15),
        maximum_response_bytes: int = 1_048_576,
    ) -> None:
        """Create a resolver with injected transport, cache, and URI policy.

        Function responsibility
        -----------------------
        Resolves protocol data through an injected source while enforcing security policy.

        Standards
        ---------
        * RFC 7517
        * RFC 7517

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        if default_ttl <= timedelta(0):
            raise ValueError("default_ttl must be positive")
        if maximum_response_bytes < 1:
            raise ValueError("maximum_response_bytes must be positive")
        self._transport = transport
        self._cache = cache
        self._uri_policy = uri_policy
        self._default_ttl = default_ttl
        self._maximum_response_bytes = maximum_response_bytes

    def get_jwks(self, uri: str, *, force_refresh: bool = False) -> JwkSet:
        """Return a validated JWK Set from cache or the remote endpoint.

        Function responsibility
        -----------------------
        Resolves protocol data through an injected source while enforcing security policy.

        Standards
        ---------
        * RFC 7517
        * RFC 7517

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        canonical_uri = self._uri_policy.validate(uri)
        if force_refresh:
            self._cache.invalidate(canonical_uri)
        else:
            cached = self._cache.get(canonical_uri)
            if cached is not None:
                return cached

        response = self._transport.get(
            canonical_uri,
            headers={"Accept": "application/jwk-set+json, application/json"},
        )
        if response.status_code != 200:
            raise ExternalServiceError(
                "JWKS endpoint returned a non-success response",
                code="jwks_http_error",
                details={"status_code": response.status_code},
            )
        if len(response.body) > self._maximum_response_bytes:
            raise ExternalServiceError(
                "JWKS response exceeds configured size limit",
                code="jwks_response_too_large",
                details={"maximum_bytes": self._maximum_response_bytes},
            )
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalServiceError(
                "JWKS endpoint did not return valid UTF-8 JSON",
                code="invalid_jwks_response",
            ) from exc
        if not isinstance(payload, dict):
            raise ExternalServiceError(
                "JWKS response root must be a JSON object",
                code="invalid_jwks_response",
            )
        try:
            jwks = JwkSet.from_untrusted_mapping(payload)
        except ValidationError as exc:
            raise ExternalServiceError(
                "JWKS response failed RFC 7517 validation",
                code="invalid_jwks_response",
                details={"errors": exc.errors(include_url=False)},
            ) from exc
        self._cache.put(canonical_uri, jwks, ttl=self._default_ttl)
        return jwks

    def resolve_key(
        self,
        uri: str,
        *,
        kid: str | None,
        alg: str | None = None,
        use: str | None = "sig",
    ) -> SupportedPublicJwk:
        """Resolve one key and refresh once when the requested key is unknown.

        Function responsibility
        -----------------------
        Resolves protocol data through an injected source while enforcing security policy.

        Standards
        ---------
        * RFC 7517
        * RFC 7517

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        jwks = self.get_jwks(uri)
        try:
            return jwks.select(kid=kid, alg=alg, use=use)
        except KeyResolutionError as first_error:
            if first_error.code != "jwks_key_not_found":
                raise
        refreshed = self.get_jwks(uri, force_refresh=True)
        return refreshed.select(kid=kid, alg=alg, use=use)
