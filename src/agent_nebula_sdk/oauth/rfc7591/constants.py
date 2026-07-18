"""Constants defined by OAuth 2.0 Dynamic Client Registration.

Standards
---------
* RFC 7591, Sections 2 and 3.
* RFC 6749, Section 2.
* RFC 7523, Section 2.2 for ``private_key_jwt`` authentication.
"""

from __future__ import annotations

DYNAMIC_CLIENT_REGISTRATION_CONTENT_TYPE = "application/json"
OAUTH_ERROR_INVALID_REDIRECT_URI = "invalid_redirect_uri"
OAUTH_ERROR_INVALID_CLIENT_METADATA = "invalid_client_metadata"
OAUTH_ERROR_INVALID_SOFTWARE_STATEMENT = "invalid_software_statement"
OAUTH_ERROR_UNAPPROVED_SOFTWARE_STATEMENT = "unapproved_software_statement"

TOKEN_ENDPOINT_AUTH_METHOD_NONE = "none"
TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC = "client_secret_basic"
TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_POST = "client_secret_post"
TOKEN_ENDPOINT_AUTH_METHOD_PRIVATE_KEY_JWT = "private_key_jwt"

GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
GRANT_TYPE_IMPLICIT = "implicit"
GRANT_TYPE_PASSWORD = "password"
GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"
GRANT_TYPE_REFRESH_TOKEN = "refresh_token"

RESPONSE_TYPE_CODE = "code"
RESPONSE_TYPE_TOKEN = "token"
