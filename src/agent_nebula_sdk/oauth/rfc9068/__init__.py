"""RFC 9068 JWT Profile for OAuth 2.0 Access Tokens.

The package exports authorization-server issuance and resource-server
validation while remaining independent of product persistence and HTTP routes.
"""

from agent_nebula_sdk.oauth.rfc9068.adapters import InMemoryAccessTokenKeyResolver
from agent_nebula_sdk.oauth.rfc9068.issuer import JwtAccessTokenIssuer
from agent_nebula_sdk.oauth.rfc9068.models import (
    AccessTokenClaims,
    AccessTokenIssueRequest,
    AccessTokenSigningKey,
    IssuedAccessToken,
    ValidatedAccessToken,
)
from agent_nebula_sdk.oauth.rfc9068.policy import Rfc9068Policy
from agent_nebula_sdk.oauth.rfc9068.ports import AccessTokenVerificationKeyResolver
from agent_nebula_sdk.oauth.rfc9068.validator import JwtAccessTokenValidator

__all__ = [
    "AccessTokenClaims",
    "AccessTokenIssueRequest",
    "AccessTokenSigningKey",
    "AccessTokenVerificationKeyResolver",
    "InMemoryAccessTokenKeyResolver",
    "IssuedAccessToken",
    "JwtAccessTokenIssuer",
    "JwtAccessTokenValidator",
    "Rfc9068Policy",
    "ValidatedAccessToken",
]
