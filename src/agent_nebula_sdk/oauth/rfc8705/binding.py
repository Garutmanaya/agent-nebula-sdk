"""RFC 8705 certificate-bound access-token validation."""
from __future__ import annotations

import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from agent_nebula_sdk.core.errors import ProtocolValidationError


def certificate_sha256_thumbprint(certificate: x509.Certificate) -> str:
    """Return the RFC 8705 ``x5t#S256`` value for a certificate."""
    digest = hashlib.sha256(certificate.public_bytes(Encoding.DER)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class CertificateBoundAccessTokenValidator:
    """Match ``cnf.x5t#S256`` to the authenticated TLS client certificate."""

    def validate(
        self,
        *,
        confirmation: dict[str, str] | None,
        certificate: x509.Certificate,
    ) -> None:
        """Reject tokens missing the RFC 8705 confirmation or bound to another cert."""
        expected = (confirmation or {}).get("x5t#S256")
        if not expected:
            raise ProtocolValidationError(
                "access token is not certificate-bound",
                code="invalid_token",
            )
        actual = certificate_sha256_thumbprint(certificate)
        if actual != expected:
            raise ProtocolValidationError(
                "access token certificate binding does not match the TLS client certificate",
                code="invalid_token",
            )
