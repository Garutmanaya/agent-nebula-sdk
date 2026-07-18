"""Shared test factories for cryptographic key material."""

from __future__ import annotations

from collections.abc import Generator

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from agent_nebula_sdk.core.encoding import encode_base64url


def integer_to_base64url(value: int) -> str:
    """Encode a positive integer using JWK base64urlUInt rules."""
    length = max(1, (value.bit_length() + 7) // 8)
    return encode_base64url(value.to_bytes(length, byteorder="big"))


@pytest.fixture(scope="session")
def rsa_public_jwk() -> dict[str, str]:
    """Return a valid 2048-bit RSA public JWK mapping."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": "rsa-2026-01",
        "use": "sig",
        "alg": "RS256",
        "n": integer_to_base64url(numbers.n),
        "e": integer_to_base64url(numbers.e),
    }


@pytest.fixture(scope="session")
def ec_public_jwk() -> dict[str, str]:
    """Return a valid P-256 public JWK mapping."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "kid": "ec-2026-01",
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "x": encode_base64url(numbers.x.to_bytes(32, byteorder="big")),
        "y": encode_base64url(numbers.y.to_bytes(32, byteorder="big")),
    }


@pytest.fixture(scope="session")
def okp_public_jwk() -> dict[str, str]:
    """Return a valid Ed25519 public JWK mapping."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    raw_public = private_key.public_key().public_bytes_raw()
    return {
        "kty": "OKP",
        "kid": "ed25519-2026-01",
        "use": "sig",
        "alg": "EdDSA",
        "crv": "Ed25519",
        "x": encode_base64url(raw_public),
    }


@pytest.fixture(autouse=True)
def no_network_by_default(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Prevent accidental socket access from unit tests.

    Integration tests use an injected transport or RESPX and therefore do not
    need direct DNS/socket access.
    """
    yield
