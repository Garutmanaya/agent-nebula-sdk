"""Strict parsing entry point for public JSON Web Keys."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import TypeAdapter, ValidationError

from agent_nebula_sdk.core.errors import KeyValidationError
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk

_PUBLIC_JWK_ADAPTER: TypeAdapter[SupportedPublicJwk] = TypeAdapter(SupportedPublicJwk)
_PRIVATE_PARAMETERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class JwkParser:
    """Parse untrusted mappings into validated public JWK objects.

    Class responsibility
    -----------------------
    Parses untrusted data into validated SDK models.

    Standards
    ---------
    * RFC 7517

    Operational notes
    -----------------
    Instances are safe to reuse when their injected collaborators are safe to reuse.
    Validation failures are reported through stable ``agent_nebula_sdk`` errors.
    """

    def parse_public_jwk(self, value: Mapping[str, Any]) -> SupportedPublicJwk:
        """Parse a Phase 1 public key while rejecting private material.

        Function responsibility
        -----------------------
        Parses untrusted data into validated SDK models.

        Standards
        ---------
        * RFC 7517

        Operational notes
        -----------------
        The function does not retain mutable protocol state unless explicitly documented.
        Validation failures are reported through stable ``agent_nebula_sdk`` errors.
        """
        private_members = sorted(_PRIVATE_PARAMETERS.intersection(value))
        if private_members:
            raise KeyValidationError(
                "public JWK contains private or symmetric key material",
                code="private_jwk_material_rejected",
                details={"members": private_members},
            )
        try:
            return _PUBLIC_JWK_ADAPTER.validate_python(dict(value))
        except ValidationError as exc:
            raise KeyValidationError(
                "JWK failed structural or cryptographic validation",
                code="invalid_public_jwk",
                details={"errors": exc.errors(include_url=False)},
            ) from exc
