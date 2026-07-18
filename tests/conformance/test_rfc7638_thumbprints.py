"""RFC 7638 thumbprint conformance vectors."""

from __future__ import annotations

from agent_nebula_sdk.jose.jwk.parser import JwkParser
from agent_nebula_sdk.jose.thumbprint.service import JwkThumbprintService


def test_rfc7638_rsa_example_vector() -> None:
    """RFC 7638 Section 3.1 produces the published SHA-256 thumbprint."""
    jwk = JwkParser().parse_public_jwk(
        {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
                "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
                "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
                "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
                "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
                "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ),
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        }
    )

    service = JwkThumbprintService()

    assert service.compute(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    assert service.canonical_json(jwk).startswith('{"e":"AQAB","kty":"RSA"')


def test_non_required_metadata_does_not_change_thumbprint(
    rsa_public_jwk: dict[str, str],
) -> None:
    """RFC 7638 excludes kid, use, and alg from the thumbprint input."""
    parser = JwkParser()
    first = parser.parse_public_jwk(rsa_public_jwk)
    second = parser.parse_public_jwk(
        {
            **rsa_public_jwk,
            "kid": "different-kid",
            "alg": "PS256",
            "use": None,
        }
    )

    service = JwkThumbprintService()

    assert service.compute(first) == service.compute(second)
    assert service.compute(first, hash_algorithm="sha384") != service.compute(first)
