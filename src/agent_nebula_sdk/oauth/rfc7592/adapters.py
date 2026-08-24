"""Reference adapters for RFC 7592 tests and local development."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from threading import RLock
from urllib.parse import quote

from agent_nebula_sdk.oauth.rfc7592.models import ClientConfigurationRecord


class UrlSafeRegistrationAccessTokenGenerator:
    """Generate high-entropy opaque RFC 7592 registration access tokens."""

    def __init__(self, *, entropy_bytes: int = 32) -> None:
        """Configure entropy used for every generated management credential."""
        if entropy_bytes < 16:
            raise ValueError("entropy_bytes must be at least 16")
        self._entropy_bytes = entropy_bytes

    def generate(self) -> str:
        """Return one cryptographically random URL-safe token."""
        return secrets.token_urlsafe(self._entropy_bytes)


class Sha256RegistrationAccessTokenCodec:
    """Hash opaque registration access tokens for reference persistence."""

    def encode(self, token: str) -> str:
        """Return a SHA-256 hexadecimal digest of the opaque token."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def matches(self, token: str, encoded_token: str) -> bool:
        """Compare a presented token to the stored digest in constant time."""
        return hmac.compare_digest(self.encode(token), encoded_token)


class BaseUrlClientConfigurationUriFactory:
    """Construct RFC 7592 client configuration URIs from a configured base URL."""

    def __init__(self, *, base_url: str) -> None:
        """Configure an HTTPS base URL controlled by the Authorization Server."""
        if not base_url.startswith("https://"):
            raise ValueError("client configuration base URL must use HTTPS")
        self._base_url = base_url.rstrip("/")

    def create(self, client_id: str) -> str:
        """Create an absolute URI containing an escaped client identifier."""
        return f"{self._base_url}/{quote(client_id, safe='')}"


class InMemoryClientConfigurationRepository:
    """Thread-safe in-memory RFC 7592 repository for tests and examples."""

    def __init__(self) -> None:
        """Create an empty managed-client repository."""
        self._records: dict[str, ClientConfigurationRecord] = {}
        self._lock = RLock()

    def find(self, client_id: str) -> ClientConfigurationRecord | None:
        """Return management state for a client, if present."""
        with self._lock:
            return self._records.get(client_id)

    def save(self, record: ClientConfigurationRecord) -> None:
        """Persist a new managed registration and reject duplicate client IDs."""
        with self._lock:
            client_id = record.client.client_id
            if client_id in self._records:
                raise ValueError("client_id already has RFC 7592 management state")
            self._records[client_id] = record

    def replace_client(self, record: ClientConfigurationRecord) -> None:
        """Replace an existing managed registration atomically."""
        with self._lock:
            client_id = record.client.client_id
            if client_id not in self._records:
                raise KeyError(client_id)
            self._records[client_id] = record

    def delete(self, client_id: str) -> None:
        """Remove management state for a deprovisioned client."""
        with self._lock:
            self._records.pop(client_id, None)
