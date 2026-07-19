"""Architecture test for the current MCP client-identification profile."""

from __future__ import annotations

from pathlib import Path


def test_mcp_package_does_not_import_rfc7591_registration() -> None:
    """Keep RFC 7591 outside the MCP package and available only to A2A/general OAuth."""
    package_root = Path("src/agent_nebula_sdk/mcp")
    source = "\n".join(path.read_text() for path in package_root.rglob("*.py"))

    assert "oauth.rfc7591" not in source
    assert "DynamicClientRegistration" not in source
