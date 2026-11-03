"""Fail-closed tool-output guard against known credential-shaped fields.

A schema-specific allowlist is still required before exposing raw firewall
configuration; this guard is a separate defence, not a security proof.
"""

from __future__ import annotations

import json
import re

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams

_SENSITIVE = frozenset(
    {
        "apikey",
        "apisecret",
        "accesstoken",
        "authtoken",
        "bearertoken",
        "bcrypt",
        "bcrypthash",
        "certdata",
        "credential",
        "credentials",
        "cryptopassword",
        "key",
        "password",
        "passwd",
        "passwordhash",
        "presharedkey",
        "privatekey",
        "psk",
        "secret",
        "sharedsecret",
        "token",
    }
)


def contains_secret_fields(value: object, depth: int = 0) -> bool:
    """Look for secret-shaped dictionary keys, including nested JSON values."""
    if depth > 100:
        return True
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[_\s-]", "", str(key)).lower()
            if normalized in _SENSITIVE:
                return True
            if contains_secret_fields(child, depth + 1):
                return True
    elif isinstance(value, list):
        return any(contains_secret_fields(item, depth + 1) for item in value)
    return False


class SecretOutputGuard(Middleware):
    """Reject entire results containing credential fields instead of leaking."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        result = await call_next(context)
        if contains_secret_fields(result.structured_content):
            raise ToolError("Tool response suppressed because it contains credential-related fields")
        for content in result.content:
            content_text = getattr(content, "text", None)
            if isinstance(content_text, str) and content_text.lstrip().startswith(("{", "[")):
                try:
                    parsed = json.loads(content_text)
                except ValueError:
                    # Non-JSON text is not treated as structured data.
                    continue
                if contains_secret_fields(parsed):
                    raise ToolError("Tool response suppressed because it contains credential-related fields")
        return result
