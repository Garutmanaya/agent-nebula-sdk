"""RFC 7523 JWT assertion profile public API.

This package exposes client-side assertion builders and authorization-server
validators without leaking PyJWT-specific types into consuming products.
"""

from agent_nebula_sdk.oauth.rfc7523.adapters import (
    InMemoryAssertionReplayStore,
    InMemoryAuthorizationGrantKeyResolver,
    InMemoryClientKeyResolver,
    InMemoryRegisteredClient,
    InMemoryRegisteredClientStore,
)
from agent_nebula_sdk.oauth.rfc7523.authenticator import PrivateKeyJwtAuthenticator
from agent_nebula_sdk.oauth.rfc7523.builder import (
    ClientAssertionBuilder,
    JwtAuthorizationGrantBuilder,
)
from agent_nebula_sdk.oauth.rfc7523.constants import (
    JWT_BEARER_ASSERTION_TYPE,
    JWT_BEARER_GRANT_TYPE,
)
from agent_nebula_sdk.oauth.rfc7523.grant import JwtAuthorizationGrantValidator
from agent_nebula_sdk.oauth.rfc7523.keys import PrivateKeyJwtSigningKey
from agent_nebula_sdk.oauth.rfc7523.models import (
    AuthenticatedClient,
    ClientAuthenticationRequest,
    JwtAuthorizationGrantRequest,
    ValidatedAuthorizationGrant,
)
from agent_nebula_sdk.oauth.rfc7523.policy import Rfc7523Policy
from agent_nebula_sdk.oauth.rfc7523.validator import JwtAssertionValidator

__all__ = [
    "JWT_BEARER_ASSERTION_TYPE",
    "JWT_BEARER_GRANT_TYPE",
    "AuthenticatedClient",
    "ClientAssertionBuilder",
    "ClientAuthenticationRequest",
    "InMemoryAssertionReplayStore",
    "InMemoryAuthorizationGrantKeyResolver",
    "InMemoryClientKeyResolver",
    "InMemoryRegisteredClient",
    "InMemoryRegisteredClientStore",
    "JwtAssertionValidator",
    "JwtAuthorizationGrantBuilder",
    "JwtAuthorizationGrantRequest",
    "JwtAuthorizationGrantValidator",
    "PrivateKeyJwtAuthenticator",
    "PrivateKeyJwtSigningKey",
    "Rfc7523Policy",
    "ValidatedAuthorizationGrant",
]
