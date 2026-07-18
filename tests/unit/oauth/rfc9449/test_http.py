"""RFC 9449 HTTP authorization, proof, and nonce header tests."""

from __future__ import annotations

import pytest

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc9449.http import DpopHttpHeaderCodec


def test_build_and_parse_dpop_authorization_headers() -> None:
    """The codec emits and parses the exact case-sensitive DPoP scheme."""
    codec = DpopHttpHeaderCodec()
    headers = codec.build_request_headers(access_token="token", proof="proof")
    assert headers.as_dict() == {
        "Authorization": "DPoP token",
        "DPoP": "proof",
    }
    assert codec.parse_authorization_header(headers.authorization) == "token"


@pytest.mark.parametrize("value", ["Bearer token", "dpop token", "DPoP", ""])
def test_reject_non_dpop_authorization_scheme(value: str) -> None:
    """Bearer downgrade and malformed authorization syntax are rejected."""
    with pytest.raises(ProtocolValidationError):
        DpopHttpHeaderCodec().parse_authorization_header(value)


def test_nonce_challenge_header() -> None:
    """Server nonces use the standard DPoP-Nonce response header."""
    assert DpopHttpHeaderCodec.build_nonce_challenge_headers("nonce") == {"DPoP-Nonce": "nonce"}


def test_http_codec_rejects_empty_values() -> None:
    """Empty tokens, proofs, and nonces are rejected before HTTP transmission."""
    codec = DpopHttpHeaderCodec()
    with pytest.raises(ValueError):
        codec.build_request_headers(access_token="", proof="proof")
    with pytest.raises(ValueError):
        codec.build_request_headers(access_token="token", proof="")
    with pytest.raises(ValueError):
        codec.build_nonce_challenge_headers("")
