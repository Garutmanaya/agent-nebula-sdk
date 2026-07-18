"""Typed public JWK models for the Phase 1 asymmetric security profile.

RFC references:
- RFC 7517, Section 4: JWK common members.
- RFC 7518, Sections 6.2 and 6.3: EC and RSA key parameters.
- RFC 8037, Section 2: OKP key parameters.

The public registration profile intentionally excludes symmetric ``oct`` keys
and all private-key parameters. Private keys remain under the control of the
service client or provider agent and are never registered with Agent Nebula.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Annotated, Literal, Self

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_nebula_sdk.core.encoding import decode_base64url, decode_base64url_uint
from agent_nebula_sdk.core.errors import KeyValidationError

_ALLOWED_PUBLIC_KEY_OPERATIONS = frozenset({"verify"})


class PublicJwk(BaseModel, ABC):
    """Common RFC 7517 members for an asymmetric public JWK."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kty: str
    kid: str | None = Field(default=None, min_length=1, max_length=255)
    use: Literal["sig", "enc"] | None = None
    key_ops: tuple[str, ...] | None = None
    alg: str | None = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_public_key_intent(self) -> Self:
        """Reject contradictory or unsafe public-key usage metadata.

        RFC 7517 permits ``use`` and ``key_ops`` but requires their semantics to
        be consistent when both are present. The Phase 1 SDK accepts signing
        verification keys and rejects operations that imply private material.
        """
        if self.key_ops is not None:
            if len(set(self.key_ops)) != len(self.key_ops):
                raise ValueError("key_ops must not contain duplicate operations")
            invalid_operations = set(self.key_ops) - _ALLOWED_PUBLIC_KEY_OPERATIONS
            if invalid_operations:
                raise ValueError("public signing JWK key_ops may contain only the verify operation")
        if self.use == "enc" and self.key_ops is not None:
            raise ValueError("encryption use is inconsistent with verify-only key_ops")
        if self.use == "sig" and self.key_ops not in (None, (), ("verify",)):
            raise ValueError("signature use is inconsistent with key_ops")
        return self

    @abstractmethod
    def to_public_key(self) -> object:
        """Convert the JWK to a ``cryptography`` public-key object.

        Concrete key-type models implement the conversion after validating all
        RFC-required public parameters. The SDK never converts private JWK
        material through this public model hierarchy.
        """

    @abstractmethod
    def required_thumbprint_members(self) -> dict[str, str]:
        """Return the canonical RFC 7638 members for this key type.

        Implementations return only the members mandated by RFC 7638 Section
        3.2; optional metadata such as ``kid`` and ``alg`` is intentionally
        excluded from the thumbprint input.
        """


class RsaPublicJwk(PublicJwk):
    """RSA public key represented as a JWK.

    ``n`` is the modulus and ``e`` is the public exponent, both encoded as
    base64url unsigned integers per RFC 7518 Section 6.3.1.
    """

    kty: Literal["RSA"]
    n: str = Field(min_length=1)
    e: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_rsa_numbers(self) -> Self:
        """Validate the RSA modulus and exponent before cryptographic use."""
        modulus = decode_base64url_uint(self.n, field_name="n")
        exponent = decode_base64url_uint(self.e, field_name="e")
        if modulus.bit_length() < 2048:
            raise ValueError("RSA modulus must be at least 2048 bits")
        if exponent < 3 or exponent % 2 == 0:
            raise ValueError("RSA public exponent must be an odd integer of at least 3")
        return self

    def to_public_key(self) -> rsa.RSAPublicKey:
        """Create an RSA public key after RFC/JWA parameter validation."""
        numbers = rsa.RSAPublicNumbers(
            e=decode_base64url_uint(self.e, field_name="e"),
            n=decode_base64url_uint(self.n, field_name="n"),
        )
        try:
            return numbers.public_key()
        except ValueError as exc:
            raise KeyValidationError(
                "RSA JWK parameters do not form a valid public key",
                code="invalid_rsa_public_key",
            ) from exc

    def required_thumbprint_members(self) -> dict[str, str]:
        """Return RFC 7638 Section 3.2 members for an RSA key."""
        return {"e": self.e, "kty": self.kty, "n": self.n}


class EcPublicJwk(PublicJwk):
    """Elliptic-curve public key represented as a JWK."""

    kty: Literal["EC"]
    crv: Literal["P-256", "P-384", "P-521"]
    x: str = Field(min_length=1)
    y: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_curve_coordinates(self) -> Self:
        """Validate coordinate length and curve membership."""
        x_bytes = decode_base64url(self.x, field_name="x")
        y_bytes = decode_base64url(self.y, field_name="y")
        expected_length = {"P-256": 32, "P-384": 48, "P-521": 66}[self.crv]
        if len(x_bytes) != expected_length or len(y_bytes) != expected_length:
            raise ValueError(f"{self.crv} coordinates must each be {expected_length} bytes")
        self.to_public_key()
        return self

    def to_public_key(self) -> ec.EllipticCurvePublicKey:
        """Create an EC public key and verify that the point is on the curve."""
        curve: ec.EllipticCurve
        if self.crv == "P-256":
            curve = ec.SECP256R1()
        elif self.crv == "P-384":
            curve = ec.SECP384R1()
        else:
            curve = ec.SECP521R1()

        numbers = ec.EllipticCurvePublicNumbers(
            x=decode_base64url_uint(self.x, field_name="x"),
            y=decode_base64url_uint(self.y, field_name="y"),
            curve=curve,
        )
        try:
            return numbers.public_key()
        except ValueError as exc:
            raise KeyValidationError(
                "EC JWK coordinates are not a valid point on the declared curve",
                code="invalid_ec_public_key",
                details={"curve": self.crv},
            ) from exc

    def required_thumbprint_members(self) -> dict[str, str]:
        """Return RFC 7638 Section 3.2 members for an EC key."""
        return {"crv": self.crv, "kty": self.kty, "x": self.x, "y": self.y}


class OkpPublicJwk(PublicJwk):
    """Ed25519 public key represented using RFC 8037 OKP parameters."""

    kty: Literal["OKP"]
    crv: Literal["Ed25519"]
    x: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_public_bytes(self) -> Self:
        """Require the 32-byte Ed25519 public-key representation."""
        public_bytes = decode_base64url(self.x, field_name="x")
        if len(public_bytes) != 32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes")
        self.to_public_key()
        return self

    def to_public_key(self) -> ed25519.Ed25519PublicKey:
        """Create an Ed25519 public key from the JWK ``x`` member."""
        try:
            return ed25519.Ed25519PublicKey.from_public_bytes(
                decode_base64url(self.x, field_name="x")
            )
        except ValueError as exc:
            raise KeyValidationError(
                "OKP JWK does not contain a valid Ed25519 public key",
                code="invalid_okp_public_key",
            ) from exc

    def required_thumbprint_members(self) -> dict[str, str]:
        """Return RFC 8037 Section A.3 thumbprint members for an OKP key."""
        return {"crv": self.crv, "kty": self.kty, "x": self.x}


SupportedPublicJwk = Annotated[
    RsaPublicJwk | EcPublicJwk | OkpPublicJwk,
    Field(discriminator="kty"),
]
