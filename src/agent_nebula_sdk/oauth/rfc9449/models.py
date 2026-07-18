"""Typed RFC 9449 DPoP proof, token-binding, and validation contracts.

RFC 9449 defines a signed proof JWT whose JOSE header carries the client's
public JWK and whose claims bind the proof to one HTTP method and target URI.
This module keeps those values typed and immutable across client,
authorization-server, and resource-server roles.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk


class DpopProofClaims(BaseModel):
    """Represent normalized claims from a DPoP proof JWT.

    Standards
    ---------
    RFC 9449 Sections 4.2 and 4.3.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    jti: str = Field(min_length=1, max_length=512)
    htm: str = Field(min_length=1, max_length=32)
    htu: str = Field(min_length=1, max_length=4096)
    iat: int
    ath: str | None = Field(default=None, min_length=1, max_length=512)
    nonce: str | None = Field(default=None, min_length=1, max_length=1024)

    @field_validator("htm")
    @classmethod
    def normalize_http_method(cls, value: str) -> str:
        """Normalize the HTTP method to uppercase for deterministic comparison."""
        normalized = value.strip().upper()
        if not normalized:
            raise ValueError("htm must not be empty")
        return normalized


class DpopConfirmation(BaseModel):
    """Represent the RFC 9449 ``cnf.jkt`` access-token binding claim."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    jkt: str = Field(min_length=1, max_length=512)


@dataclass(frozen=True, slots=True)
class DpopSigningKey:
    """Carry the client's DPoP private key and public JWK metadata.

    The SDK never persists this key. Host applications own secure private-key
    storage and pass the selected key only for one proof-building operation.
    """

    algorithm: str
    private_key: object
    public_jwk: SupportedPublicJwk

    def __post_init__(self) -> None:
        """Reject an incomplete algorithm before proof construction."""
        if not self.algorithm.strip():
            raise ValueError("algorithm must not be empty")


class DpopProofBuildRequest(BaseModel):
    """Describe one request-specific proof to be signed by a DPoP client."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    http_method: str = Field(min_length=1, max_length=32)
    target_uri: str = Field(min_length=1, max_length=4096)
    access_token: str | None = Field(default=None, min_length=1)
    nonce: str | None = Field(default=None, min_length=1, max_length=1024)


class BuiltDpopProof(BaseModel):
    """Return a compact proof JWT and the trusted values used to build it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proof: str
    claims: DpopProofClaims
    key_thumbprint: str
    algorithm: str


class ValidatedDpopProof(BaseModel):
    """Return a proof result safe for token issuance or resource policy."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid", frozen=True)

    claims: DpopProofClaims
    public_jwk: SupportedPublicJwk
    key_thumbprint: str
    algorithm: str


class DpopBoundTokenContext(BaseModel):
    """Represent a validated access token bound to one DPoP public key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    access_token: str
    key_thumbprint: str
