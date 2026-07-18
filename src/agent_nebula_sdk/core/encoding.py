"""Strict base64url helpers used by JOSE protocol modules."""

from __future__ import annotations

import base64
import binascii
import re

from agent_nebula_sdk.core.errors import ProtocolValidationError

_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]*$")


def decode_base64url_uint(value: str, *, field_name: str) -> int:
    """Decode an unpadded base64url-encoded unsigned integer.

    RFC 7517 key parameters use the base64url encoding rules from JWS/JWA.
    Empty values, padding, non-alphabet characters, and zero-length integers
    are rejected instead of being silently normalized.
    """
    decoded = decode_base64url(value, field_name=field_name)
    if not decoded:
        raise ProtocolValidationError(
            f"{field_name} must not decode to an empty integer",
            code="invalid_base64url_integer",
            details={"field": field_name},
        )
    return int.from_bytes(decoded, byteorder="big", signed=False)


def decode_base64url(value: str, *, field_name: str) -> bytes:
    """Decode strict, unpadded base64url text into bytes."""
    if not value:
        raise ProtocolValidationError(
            f"{field_name} must not be empty",
            code="empty_base64url_value",
            details={"field": field_name},
        )
    if "=" in value or _BASE64URL_PATTERN.fullmatch(value) is None:
        raise ProtocolValidationError(
            f"{field_name} is not valid unpadded base64url text",
            code="invalid_base64url_value",
            details={"field": field_name},
        )

    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, binascii.Error) as exc:
        raise ProtocolValidationError(
            f"{field_name} could not be decoded as base64url",
            code="invalid_base64url_value",
            details={"field": field_name},
        ) from exc


def encode_base64url(value: bytes) -> str:
    """Encode bytes using unpadded base64url representation."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
