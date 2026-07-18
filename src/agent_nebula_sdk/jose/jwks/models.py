"""Typed JSON Web Key Set model and deterministic key selection."""

from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_nebula_sdk.core.errors import DuplicateKeyIdentifierError, KeyResolutionError
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk


class JwkSet(BaseModel):
    """RFC 7517 Section 5 JWK Set containing validated public keys."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    keys: tuple[SupportedPublicJwk, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def reject_duplicate_key_identifiers(self) -> Self:
        """Reject ambiguous duplicate non-empty ``kid`` values."""
        key_ids = [key.kid for key in self.keys if key.kid is not None]
        duplicates = sorted({key_id for key_id in key_ids if key_ids.count(key_id) > 1})
        if duplicates:
            raise DuplicateKeyIdentifierError(
                "JWK Set contains duplicate key identifiers",
                code="duplicate_jwks_kid",
                details={"kids": duplicates},
            )
        return self

    @classmethod
    def from_untrusted_mapping(cls, value: dict[str, Any]) -> JwkSet:
        """Parse an untrusted RFC 7517 JWK Set document."""
        return cls.model_validate(value)

    def select(
        self,
        *,
        kid: str | None,
        alg: str | None = None,
        use: str | None = "sig",
    ) -> SupportedPublicJwk:
        """Select exactly one key matching JOSE header and usage constraints.

        A missing ``kid`` is accepted only when the filtered JWK Set contains a
        single unambiguous candidate. This prevents arbitrary first-key selection.
        """
        candidates = list(self.keys)
        if kid is not None:
            candidates = [key for key in candidates if key.kid == kid]
        if alg is not None:
            candidates = [key for key in candidates if key.alg in (None, alg)]
        if use is not None:
            candidates = [key for key in candidates if key.use in (None, use)]

        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise KeyResolutionError(
                "no JWK matches the requested key identifier and constraints",
                code="jwks_key_not_found",
                details={"kid": kid, "alg": alg, "use": use},
            )
        raise KeyResolutionError(
            "JWK selection is ambiguous",
            code="ambiguous_jwks_key",
            details={"kid": kid, "candidate_count": len(candidates)},
        )
