"""Constants registered by RFC 8707 Resource Indicators for OAuth 2.0.

Standards
---------
RFC 8707 Sections 2 and 5 register the ``resource`` request parameter and the
``invalid_target`` OAuth extension error. Keeping these protocol values in one
module prevents string duplication across clients, authorization servers, and
resource-server validators.
"""

RESOURCE_PARAMETER = "resource"
"""OAuth request parameter carrying a protected-resource identifier."""

INVALID_TARGET_ERROR = "invalid_target"
"""OAuth error returned for an invalid, missing, unknown, or malformed target."""
