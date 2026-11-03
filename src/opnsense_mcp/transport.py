"""Runtime transport configuration for the single-process OPNsense MCP server.

HTTP always requires a bearer token. No other service or proxy is necessary.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Literal

from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

Transport = Literal["stdio", "http"]
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._~+/=-]{32,256}\Z")


@dataclass(frozen=True, repr=False)
class TransportConfig:
    """Validated MCP transport settings; bearer token is excluded from repr."""

    transport: Transport
    host: str
    port: int
    token: str | None

    def __repr__(self) -> str:
        return f"TransportConfig(transport={self.transport!r}, host={self.host!r}, port={self.port})"


def load_transport_config() -> TransportConfig:
    """Reject unsafe or incomplete remote-server configurations at startup."""
    value = os.environ.get("OPNSENSE_MCP_TRANSPORT", "stdio").strip().lower()
    if value not in {"stdio", "http"}:
        raise ValueError("OPNSENSE_MCP_TRANSPORT must be stdio or http")
    if value == "stdio":
        return TransportConfig(transport="stdio", host="", port=0, token=None)

    token = os.environ.get("OPNSENSE_MCP_AUTH_TOKEN", "")
    if not _TOKEN_PATTERN.fullmatch(token):
        raise ValueError("OPNSENSE_MCP_AUTH_TOKEN must be 32-256 ASCII token characters")

    host = os.environ.get("OPNSENSE_MCP_HOST", "127.0.0.1").strip()
    if not host:
        raise ValueError("OPNSENSE_MCP_HOST must not be empty")
    try:
        port = int(os.environ.get("OPNSENSE_MCP_PORT", "8000"))
    except ValueError as exc:
        raise ValueError("OPNSENSE_MCP_PORT must be an integer") from exc
    if port < 1 or port > 65535:
        raise ValueError("OPNSENSE_MCP_PORT must be between 1 and 65535")
    return TransportConfig(transport="http", host=host, port=port, token=token)


def build_auth(config: TransportConfig) -> StaticTokenVerifier | None:
    """Use FastMCP's built-in bearer verifier for authenticated HTTP requests."""
    if config.transport == "stdio":
        return None
    if config.token is None:
        raise ValueError("HTTP mode requires a bearer token")
    return StaticTokenVerifier(
        tokens={
            config.token: {
                "sub": "openwebui",
                "client_id": "openwebui",
                "scopes": ["opnsense:read"],
            }
        },
        required_scopes=["opnsense:read"],
    )
