"""Protocol-neutral authentication models shared by server integrations."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True, slots=True)
class AuthenticatedIdentity:
    """Identity established by a generic credential verifier."""
    subject: str
    attributes: dict[str, Any]
