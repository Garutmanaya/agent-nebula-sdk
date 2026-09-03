"""Typed resource-server security context models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from agent_nebula_sdk.oauth.rfc9068 import AccessTokenClaims
from agent_nebula_sdk.oauth.rfc9449 import ValidatedDpopProof


class ResourceSecurityContext(BaseModel):
    """Carry trusted token and proof data into provider-local authorization policy."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid", frozen=True)

    subject: str
    client_id: str
    claims: AccessTokenClaims
    dpop_proof: ValidatedDpopProof | None = None
