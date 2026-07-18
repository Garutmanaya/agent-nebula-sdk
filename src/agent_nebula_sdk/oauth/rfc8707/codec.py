"""Transport codecs for repeated RFC 8707 ``resource`` parameters.

OAuth form encoding permits a parameter name to occur more than once. Mapping
objects lose duplicate keys, so this module uses ordered key-value pairs and
provides helpers for form-encoded token requests and JWT authorization requests.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from urllib.parse import parse_qsl, urlencode

from agent_nebula_sdk.core.errors import ProtocolValidationError
from agent_nebula_sdk.oauth.rfc8707.constants import INVALID_TARGET_ERROR, RESOURCE_PARAMETER
from agent_nebula_sdk.oauth.rfc8707.models import ResourceIndicatorRequest


class ResourceParameterCodec:
    """Encode and decode RFC 8707 parameters without losing repeated values."""

    def encode_form(
        self,
        parameters: Iterable[tuple[str, str]],
        request: ResourceIndicatorRequest,
    ) -> bytes:
        """Append repeated resource parameters to an OAuth form body."""
        pairs = list(parameters)
        pairs.extend((RESOURCE_PARAMETER, resource) for resource in request.resources)
        return urlencode(pairs).encode("ascii")

    def decode_form(self, body: bytes) -> ResourceIndicatorRequest:
        """Extract all resource values from an application/x-www-form-urlencoded body."""
        try:
            text = body.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProtocolValidationError(
                "OAuth form body is not valid ASCII",
                code=INVALID_TARGET_ERROR,
            ) from exc
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=False)
        resources = tuple(value for name, value in pairs if name == RESOURCE_PARAMETER)
        return ResourceIndicatorRequest(resources=resources)

    def decode_jwt_claim(self, payload: Mapping[str, object]) -> ResourceIndicatorRequest:
        """Decode the string-or-array representation used in JWT authorization requests.

        RFC 8707 Section 2.1 represents one resource as a JSON string and
        multiple resources as an array of strings.
        """
        value = payload.get(RESOURCE_PARAMETER)
        if value is None:
            return ResourceIndicatorRequest()
        if isinstance(value, str):
            return ResourceIndicatorRequest(resources=(value,))
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return ResourceIndicatorRequest(resources=tuple(value))
        raise ProtocolValidationError(
            "JWT resource claim must be a string or array of strings",
            code=INVALID_TARGET_ERROR,
        )
