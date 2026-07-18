"""Constants for the RFC 9068 JWT access-token profile.

The values in this module are protocol constants rather than deployment
configuration. Keeping them centralized prevents drift between issuers,
validators, tests, and future HTTP adapters.
"""

from __future__ import annotations

ACCESS_TOKEN_TYPE = "at+jwt"
APPLICATION_ACCESS_TOKEN_TYPE = "application/at+jwt"
INVALID_TOKEN_ERROR = "invalid_token"
REQUIRED_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "jti", "client_id"})
REGISTERED_AUTHORIZATION_CLAIMS = frozenset({"scope", "groups", "roles", "entitlements"})
