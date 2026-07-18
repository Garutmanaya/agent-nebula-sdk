"""Adversarial and branch tests for JWK policy and conversion."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from agent_nebula_sdk.core.encoding import encode_base64url
from agent_nebula_sdk.core.errors import KeyValidationError
from agent_nebula_sdk.jose.jwk.parser import JwkParser


def integer_to_base64url(value: int) -> str:
    """Encode an integer as unpadded base64urlUInt for test keys."""
    length = max(1, (value.bit_length() + 7) // 8)
    return encode_base64url(value.to_bytes(length, byteorder="big"))


@pytest.mark.parametrize(
    ("curve", "name", "coordinate_size"),
    [
        (ec.SECP384R1(), "P-384", 48),
        (ec.SECP521R1(), "P-521", 66),
    ],
)
def test_supports_additional_nist_curves(
    curve: ec.EllipticCurve,
    name: str,
    coordinate_size: int,
) -> None:
    """P-384 and P-521 branches convert valid curve points."""
    private_key = ec.generate_private_key(curve)
    numbers = private_key.public_key().public_numbers()
    candidate: dict[str, Any] = {
        "kty": "EC",
        "crv": name,
        "x": encode_base64url(numbers.x.to_bytes(coordinate_size, "big")),
        "y": encode_base64url(numbers.y.to_bytes(coordinate_size, "big")),
    }

    parsed = JwkParser().parse_public_jwk(candidate)

    assert parsed.to_public_key().curve.name == curve.name


def test_rejects_invalid_ec_coordinate_length(ec_public_jwk: dict[str, str]) -> None:
    """Coordinates must have the fixed width required by the declared curve."""
    with pytest.raises(KeyValidationError):
        JwkParser().parse_public_jwk({**ec_public_jwk, "x": "AQ"})


def test_rejects_point_not_on_curve(ec_public_jwk: dict[str, str]) -> None:
    """Mathematically invalid points are rejected before signature verification."""
    with pytest.raises(KeyValidationError):
        JwkParser().parse_public_jwk(
            {
                **ec_public_jwk,
                "x": encode_base64url(b"\x01" * 32),
                "y": encode_base64url(b"\x01" * 32),
            }
        )


def test_rejects_invalid_okp_length(okp_public_jwk: dict[str, str]) -> None:
    """Ed25519 public keys must contain exactly 32 bytes."""
    with pytest.raises(KeyValidationError):
        JwkParser().parse_public_jwk({**okp_public_jwk, "x": "AQ"})


def test_rejects_even_rsa_exponent(rsa_public_jwk: dict[str, str]) -> None:
    """An even RSA exponent is invalid by the active key policy."""
    with pytest.raises(KeyValidationError):
        JwkParser().parse_public_jwk({**rsa_public_jwk, "e": "Ag"})


def test_rejects_duplicate_key_operations(rsa_public_jwk: dict[str, str]) -> None:
    """Duplicate key operations are rejected as contradictory metadata."""
    with pytest.raises(KeyValidationError):
        JwkParser().parse_public_jwk({**rsa_public_jwk, "key_ops": ["verify", "verify"]})


def test_rejects_encryption_use_with_verify_operation(rsa_public_jwk: dict[str, str]) -> None:
    """The common use and key_ops members must describe compatible intent."""
    with pytest.raises(KeyValidationError):
        JwkParser().parse_public_jwk({**rsa_public_jwk, "use": "enc", "key_ops": ["verify"]})
