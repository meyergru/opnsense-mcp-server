"""End-to-end FastMCP surface for errors: a certificate failure must reach caller."""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.error_results import ErrorResultMiddleware


@pytest.mark.asyncio
async def test_certificate_error_reaches_mcp_caller_as_structured_iserror() -> None:
    mcp = FastMCP("test-errors", mask_error_details=True)
    mcp.add_middleware(ErrorResultMiddleware())

    @mcp.tool()
    async def broken(site: str = "") -> dict:
        raise OPNsenseAPIError("SECRET downstream https://hidden.invalid/path", code="tls_hostname_mismatch")

    result = await mcp.call_tool("broken", {"site": "opnsense.thomas"})
    assert result.is_error is True
    assert result.structured_content is not None
    assert result.structured_content["ok"] is False
    assert result.structured_content["site"] == "opnsense.thomas"
    assert result.structured_content["error"]["type"] == "tls_hostname_mismatch"
    assert "certificate" in result.structured_content["error"]["message"].lower()
    assert "SECRET" not in str(result)


@pytest.mark.asyncio
async def test_http_401_error_reaches_mcp_caller_without_raw_body() -> None:
    mcp = FastMCP("test-errors", mask_error_details=True)
    mcp.add_middleware(ErrorResultMiddleware())

    @mcp.tool()
    async def broken() -> dict:
        raise OPNsenseAPIError("raw user credentials", status_code=401)

    result = await mcp.call_tool("broken", {})
    assert result.is_error is True
    assert result.structured_content["error"] == {
        "type": "authentication_failed",
        "message": "OPNsense rejected the configured API credentials",
        "http_status": 401,
    }
    assert "raw user credentials" not in str(result)
