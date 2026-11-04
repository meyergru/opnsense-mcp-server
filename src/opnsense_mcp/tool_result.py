"""Normalize OPNsense table responses into MCP-compatible structured objects.

Some OPNsense endpoints return a JSON array at the root, but MCP structured
content must be a JSON object. Preserve object responses as-is.
"""

from __future__ import annotations

from typing import Any, cast

from opnsense_mcp.api_client import OPNsenseAPIError


def structured_table_result(value: object) -> dict[str, Any]:
    """Return a structured MCP response for an OPNsense table endpoint."""
    if isinstance(value, dict):
        return cast(dict[str, Any], value)
    if isinstance(value, list):
        return {"rows": value, "rowCount": len(value)}
    raise OPNsenseAPIError(
        f"Unexpected table response type: {type(value).__name__} (expected object or array)"
    )
