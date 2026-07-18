"""Bind RFC 9068 access-token issuance and validation to RFC 9449 DPoP keys."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9449.constants import (
    CONFIRMATION_CLAIM,
    INVALID_DPOP_PROOF,
    JWK_THUMBPRINT_CLAIM,
)
from agent_nebula_sdk.oauth.rfc9449.models import DpopConfirmation


class DpopTokenBindingService:
    """Create and parse the RFC 9449 ``cnf.jkt`` confirmation claim."""

    def build_confirmation_claim(self, key_thumbprint: str) -> dict[str, dict[str, str]]:
        """Return a collision-safe claim mapping for RFC 9068 token issuance."""
        confirmation = DpopConfirmation(jkt=key_thumbprint)
        return {CONFIRMATION_CLAIM: confirmation.model_dump()}

    def extract_key_thumbprint(self, claims: Mapping[str, Any]) -> str:
        """Read and validate ``cnf.jkt`` from a trusted access-token claims set."""
        value = claims.get(CONFIRMATION_CLAIM)
        try:
            confirmation = DpopConfirmation.model_validate(value)
        except (TypeError, ValueError) as exc:
            raise ProtocolValidationError(
                "access token does not contain a valid cnf.jkt binding",
                code=INVALID_DPOP_PROOF,
            ) from exc
        return confirmation.jkt

    @staticmethod
    def is_dpop_bound(claims: Mapping[str, Any]) -> bool:
        """Return whether a structurally valid ``cnf.jkt`` member is present."""
        confirmation = claims.get(CONFIRMATION_CLAIM)
        return (
            isinstance(confirmation, dict)
            and isinstance(confirmation.get(JWK_THUMBPRINT_CLAIM), str)
            and bool(confirmation[JWK_THUMBPRINT_CLAIM].strip())
        )
