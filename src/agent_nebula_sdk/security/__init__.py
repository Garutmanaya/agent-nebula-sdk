"""Protocol-neutral authentication primitives."""

from .api_key import ApiKeyAuthenticator, ApiKeyCredentialVerifier, ApiKeyRequest
from .http_auth import BasicCredentialDecoder, HttpAuthAuthenticator, HttpCredentialVerifier
from .models import AuthenticatedIdentity
from .mtls import MtlsClientCertificateAuthenticator, MtlsTrustPolicy
from .oidc import OidcJwtAuthenticator, OidcVerificationKeyResolver

__all__ = [
    "ApiKeyAuthenticator",
    "ApiKeyCredentialVerifier",
    "ApiKeyRequest",
    "AuthenticatedIdentity",
    "BasicCredentialDecoder",
    "HttpAuthAuthenticator",
    "HttpCredentialVerifier",
    "MtlsClientCertificateAuthenticator",
    "MtlsTrustPolicy",
    "OidcJwtAuthenticator",
    "OidcVerificationKeyResolver",
]
