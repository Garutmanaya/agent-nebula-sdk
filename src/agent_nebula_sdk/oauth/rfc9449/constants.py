"""Protocol constants for RFC 9449 Demonstrating Proof of Possession.

The constants are shared by proof builders, validators, token-binding helpers,
and later HTTP adapters. Keeping them in one module prevents string drift in
security-sensitive JOSE and OAuth processing.
"""

from __future__ import annotations

DPOP_PROOF_TYPE = "dpop+jwt"
DPOP_AUTHORIZATION_SCHEME = "DPoP"
DPOP_HEADER_NAME = "DPoP"
DPOP_NONCE_HEADER_NAME = "DPoP-Nonce"
CONFIRMATION_CLAIM = "cnf"
JWK_THUMBPRINT_CLAIM = "jkt"
ACCESS_TOKEN_HASH_CLAIM = "ath"
INVALID_DPOP_PROOF = "invalid_dpop_proof"
USE_DPOP_NONCE = "use_dpop_nonce"
