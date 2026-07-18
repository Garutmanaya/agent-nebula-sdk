"""Unit tests for strict JOSE base64url encoding helpers."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.encoding import decode_base64url, decode_base64url_uint, encode_base64url
from agent_nebula_sdk.core.errors import ProtocolValidationError


def test_base64url_round_trip() -> None:
    """Unpadded base64url encoding round-trips arbitrary bytes."""
    value = b"agent-nebula\x00sdk"

    assert decode_base64url(encode_base64url(value), field_name="value") == value


@pytest.mark.parametrize("value", ["", "AQ==", "not valid!"])
def test_rejects_invalid_base64url(value: str) -> None:
    """Empty, padded, and non-alphabet input is rejected."""
    with pytest.raises(ProtocolValidationError):
        decode_base64url(value, field_name="value")


def test_rejects_empty_integer() -> None:
    """An empty base64urlUInt is not a valid JOSE integer."""
    with pytest.raises(ProtocolValidationError):
        decode_base64url_uint("", field_name="n")
