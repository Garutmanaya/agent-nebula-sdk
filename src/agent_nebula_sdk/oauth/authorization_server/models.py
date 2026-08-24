"""Typed authorization-server orchestration models."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_nebula_sdk.oauth.rfc7523 import ClientAuthenticationRequest
from agent_nebula_sdk.oauth.rfc9068 import IssuedAccessToken
from agent_nebula_sdk.oauth.rfc9449 import ValidatedDpopProof


class TokenIssuanceRequest(BaseModel):
    """Describe one authenticated, resource-targeted token issuance operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    client_authentication: ClientAuthenticationRequest
    dpop_proof: str = Field(min_length=1)
    token_endpoint: str = Field(min_length=1, max_length=4096)
    resource: str = Field(min_length=1, max_length=4096)
    issuer: str = Field(min_length=1, max_length=2048)
    subject: str | None = None
    scope: tuple[str, ...] = ()
    additional_claims: Mapping[str, Any] = Field(default_factory=dict)
    nonce_context: str | None = None


class TokenIssuanceResult(BaseModel):
    """Return a token together with the validated client and DPoP proof context."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid", frozen=True)

    access_token: IssuedAccessToken
    client_id: str
    audience: str
    dpop_proof: ValidatedDpopProof
