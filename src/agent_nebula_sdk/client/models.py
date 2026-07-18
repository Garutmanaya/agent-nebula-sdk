"""Typed client-role request and result models.

The role facade models combine RFC-specific values without hiding the underlying
standards. They contain no network, persistence, or product-specific behavior.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agent_nebula_sdk.oauth.rfc7523.models import ClientAuthenticationRequest
from agent_nebula_sdk.oauth.rfc9449.models import BuiltDpopProof


class TokenRequestArtifacts(BaseModel):
    """Carry form fields and DPoP proof required for one OAuth token request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    form_fields: dict[str, str | tuple[str, ...]]
    client_authentication: ClientAuthenticationRequest
    dpop_proof: BuiltDpopProof


class ProtectedRequestArtifacts(BaseModel):
    """Carry HTTP authorization headers for one DPoP-protected request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    headers: dict[str, str]
    dpop_proof: BuiltDpopProof


class ClientTokenRequest(BaseModel):
    """Describe a client-credentials token request for one protected resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid", frozen=True)

    client_id: str = Field(min_length=1, max_length=255)
    token_endpoint: str = Field(min_length=1, max_length=4096)
    resource: str = Field(min_length=1, max_length=4096)
    scope: tuple[str, ...] = ()
    nonce: str | None = None
