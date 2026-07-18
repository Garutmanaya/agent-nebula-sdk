"""Constants defined by RFC 7521 and RFC 7523.

The constants are centralized to prevent product code from duplicating or
mistyping the registered OAuth assertion parameter values.
"""

from __future__ import annotations

JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
