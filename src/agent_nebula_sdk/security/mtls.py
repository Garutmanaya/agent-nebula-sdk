"""Generic mutual-TLS client-certificate trust validation."""
from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from agent_nebula_sdk.core.errors import ProtocolValidationError

from .models import AuthenticatedIdentity


@dataclass(frozen=True, slots=True)
class MtlsTrustPolicy:
    """Trust anchors and optional intermediates used to authenticate client certificates."""

    trust_anchors: tuple[x509.Certificate, ...]
    intermediates: tuple[x509.Certificate, ...] = ()

    @classmethod
    def from_pem(
        cls,
        *,
        trust_bundle_pem: bytes,
        intermediates_pem: bytes | None = None,
    ) -> MtlsTrustPolicy:
        """Parse PEM trust material into an immutable validation policy."""
        anchors = tuple(x509.load_pem_x509_certificates(trust_bundle_pem))
        if not anchors:
            raise ValueError("mTLS trust bundle must contain at least one certificate")
        intermediates = (
            tuple(x509.load_pem_x509_certificates(intermediates_pem))
            if intermediates_pem
            else ()
        )
        return cls(trust_anchors=anchors, intermediates=intermediates)


class MtlsClientCertificateAuthenticator:
    """Validate a presented X.509 client certificate against configured trust anchors."""

    def __init__(self, policy: MtlsTrustPolicy) -> None:
        """Build a reusable client-certificate verifier from trusted roots."""
        self._policy = policy
        self._verifier = (
            PolicyBuilder().store(Store(list(policy.trust_anchors))).build_client_verifier()
        )

    def authenticate(self, peer_certificate: bytes) -> AuthenticatedIdentity:
        """Validate the certificate chain and return the authenticated X.509 subject."""
        try:
            certificate = self._load(peer_certificate)
            verified_client = self._verifier.verify(
                certificate,
                list(self._policy.intermediates),
            )
        except (ValueError, VerificationError) as exc:
            raise ProtocolValidationError(
                "mTLS client certificate validation failed",
                code="invalid_client_certificate",
            ) from exc
        subject = certificate.subject.rfc4514_string()
        if not subject:
            raise ProtocolValidationError(
                "mTLS client certificate has no subject",
                code="invalid_client_certificate",
            )
        return AuthenticatedIdentity(
            subject=subject,
            attributes={"certificate": certificate, "verified_client": verified_client},
        )

    @staticmethod
    def _load(value: bytes) -> x509.Certificate:
        """Load a PEM or DER encoded X.509 certificate."""
        if b"-----BEGIN CERTIFICATE-----" in value:
            return x509.load_pem_x509_certificate(value)
        return x509.load_der_x509_certificate(value)
