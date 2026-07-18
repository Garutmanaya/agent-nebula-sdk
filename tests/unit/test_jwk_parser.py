"""Unit tests for strict RFC 7517 public JWK parsing."""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from agent_nebula_sdk.core.errors import KeyValidationError
from agent_nebula_sdk.jose.jwk.models import EcPublicJwk, OkpPublicJwk, RsaPublicJwk
from agent_nebula_sdk.jose.jwk.parser import JwkParser


def test_parses_rsa_public_jwk(rsa_public_jwk: dict[str, str]) -> None:
    """A valid RSA JWK is converted to a typed model and public key."""
    parsed = JwkParser().parse_public_jwk(rsa_public_jwk)

    assert isinstance(parsed, RsaPublicJwk)
    assert isinstance(parsed.to_public_key(), rsa.RSAPublicKey)


def test_parses_ec_public_jwk(ec_public_jwk: dict[str, str]) -> None:
    """A valid P-256 JWK is converted to a typed model and public key."""
    parsed = JwkParser().parse_public_jwk(ec_public_jwk)

    assert isinstance(parsed, EcPublicJwk)
    assert isinstance(parsed.to_public_key(), ec.EllipticCurvePublicKey)


def test_parses_okp_public_jwk(okp_public_jwk: dict[str, str]) -> None:
    """A valid Ed25519 JWK is converted to a typed model and public key."""
    parsed = JwkParser().parse_public_jwk(okp_public_jwk)

    assert isinstance(parsed, OkpPublicJwk)
    assert isinstance(parsed.to_public_key(), ed25519.Ed25519PublicKey)


@pytest.mark.parametrize("private_member", ["d", "p", "q", "dp", "dq", "qi", "k"])
def test_rejects_private_or_symmetric_material(
    rsa_public_jwk: dict[str, str],
    private_member: str,
) -> None:
    """Public registration never accepts private or symmetric JWK members."""
    candidate: dict[str, Any] = {**rsa_public_jwk, private_member: "secret"}

    with pytest.raises(KeyValidationError) as error:
        JwkParser().parse_public_jwk(candidate)

    assert error.value.code == "private_jwk_material_rejected"


def test_rejects_weak_rsa_modulus(rsa_public_jwk: dict[str, str]) -> None:
    """The SDK Phase 1 policy rejects RSA keys below 2048 bits."""
    candidate = {**rsa_public_jwk, "n": "AQAB"}

    with pytest.raises(KeyValidationError) as error:
        JwkParser().parse_public_jwk(candidate)

    assert error.value.code == "invalid_public_jwk"


def test_rejects_private_key_operation(rsa_public_jwk: dict[str, str]) -> None:
    """Public signing JWK metadata cannot request a private sign operation."""
    candidate: dict[str, Any] = {**rsa_public_jwk, "key_ops": ["sign"]}

    with pytest.raises(KeyValidationError):
        JwkParser().parse_public_jwk(candidate)
