"""Reusable cryptographic and time fixtures for RFC 7523 tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from agent_nebula_sdk.core.encoding import encode_base64url
from agent_nebula_sdk.jose.jwk.models import SupportedPublicJwk
from agent_nebula_sdk.jose.jwk.parser import JwkParser


def integer_to_base64url(value: int) -> str:
    """Encode a positive integer using the JWK base64urlUInt representation."""
    length = max(1, (value.bit_length() + 7) // 8)
    return encode_base64url(value.to_bytes(length, byteorder="big"))


@dataclass(slots=True)
class FixedClock:
    """Mutable deterministic clock used by builders and validators."""

    current: datetime = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        """Return the configured test instant."""
        return self.current


def build_rsa_key_pair() -> tuple[rsa.RSAPrivateKey, SupportedPublicJwk]:
    """Generate an RSA private key and matching validated public JWK."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    public_jwk = JwkParser().parse_public_jwk(
        {
            "kty": "RSA",
            "kid": "rsa-client-2026-01",
            "use": "sig",
            "alg": "RS256",
            "n": integer_to_base64url(numbers.n),
            "e": integer_to_base64url(numbers.e),
        }
    )
    return private_key, public_jwk


def build_ec_key_pair() -> tuple[ec.EllipticCurvePrivateKey, SupportedPublicJwk]:
    """Generate a P-256 private key and matching validated public JWK."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    public_jwk = JwkParser().parse_public_jwk(
        {
            "kty": "EC",
            "kid": "ec-client-2026-01",
            "use": "sig",
            "alg": "ES256",
            "crv": "P-256",
            "x": encode_base64url(numbers.x.to_bytes(32, byteorder="big")),
            "y": encode_base64url(numbers.y.to_bytes(32, byteorder="big")),
        }
    )
    return private_key, public_jwk


def build_ed25519_key_pair() -> tuple[ed25519.Ed25519PrivateKey, SupportedPublicJwk]:
    """Generate an Ed25519 private key and matching validated public JWK."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_jwk = JwkParser().parse_public_jwk(
        {
            "kty": "OKP",
            "kid": "ed-client-2026-01",
            "use": "sig",
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": encode_base64url(private_key.public_key().public_bytes_raw()),
        }
    )
    return private_key, public_jwk
