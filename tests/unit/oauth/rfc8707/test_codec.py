"""Unit tests for RFC 8707 form and JWT parameter codecs."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8707 import (
    ResourceIndicatorRequest,
    ResourceParameterCodec,
)


def test_form_codec_preserves_repeated_resource_parameters() -> None:
    """OAuth form encoding retains one resource parameter per target."""
    codec = ResourceParameterCodec()
    request = ResourceIndicatorRequest(resources=("https://one.example/", "https://two.example/"))
    body = codec.encode_form((("grant_type", "client_credentials"),), request)
    decoded = codec.decode_form(body)
    assert decoded.resources == request.resources
    assert b"grant_type=client_credentials" in body


def test_jwt_codec_accepts_single_string() -> None:
    """One JWT authorization-request resource is represented as a string."""
    codec = ResourceParameterCodec()
    request = codec.decode_jwt_claim({"resource": "https://one.example/"})
    assert request.resources == ("https://one.example/",)


def test_jwt_codec_accepts_string_array() -> None:
    """Multiple JWT authorization-request resources are represented as an array."""
    codec = ResourceParameterCodec()
    request = codec.decode_jwt_claim({"resource": ["https://one.example/", "https://two.example/"]})
    assert request.resources == ("https://one.example/", "https://two.example/")


def test_jwt_codec_rejects_mixed_array() -> None:
    """Non-string values cannot become protected-resource identifiers."""
    codec = ResourceParameterCodec()
    with pytest.raises(ProtocolValidationError) as error:
        codec.decode_jwt_claim({"resource": ["https://one.example/", 7]})
    assert error.value.code == "invalid_target"


def test_form_codec_rejects_non_ascii_body() -> None:
    """Malformed OAuth form bytes are normalized as invalid_target."""
    codec = ResourceParameterCodec()
    with pytest.raises(ProtocolValidationError):
        codec.decode_form(b"resource=\xff")
