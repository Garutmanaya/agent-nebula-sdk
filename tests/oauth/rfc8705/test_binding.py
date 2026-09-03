from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8705 import (
    CertificateBoundAccessTokenValidator,
    certificate_sha256_thumbprint,
)


def _certificate() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_certificate_binding_matches_x5t_s256() -> None:
    certificate = _certificate()
    CertificateBoundAccessTokenValidator().validate(
        confirmation={"x5t#S256": certificate_sha256_thumbprint(certificate)},
        certificate=certificate,
    )


def test_certificate_binding_rejects_mismatch() -> None:
    with pytest.raises(ProtocolValidationError):
        CertificateBoundAccessTokenValidator().validate(
            confirmation={"x5t#S256": "wrong"},
            certificate=_certificate(),
        )
