"""OPNsense MCP Server — FastMCP entrypoint.

Registers all tool modules and starts the STDIO server.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
import os
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.server.lifespan import lifespan
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from opnsense_mcp import __version__
from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config_cache import ConfigCache
from opnsense_mcp.targets import TargetRegistry


@lifespan
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Initialize the OPNsense API client, savepoint manager, and config cache."""
    targets = TargetRegistry.from_environment()
    try:
        yield {"targets": targets}
    finally:
        await targets.close()


def _transport() -> str:
    """Choose the supported MCP transport; never enable HTTP implicitly."""
    value = os.environ.get("OPNSENSE_MCP_TRANSPORT", "stdio").strip().lower()
    if value not in {"stdio", "http"}:
        raise ValueError("OPNSENSE_MCP_TRANSPORT must be stdio or http")
    return value


def _http_auth() -> StaticTokenVerifier | None:
    """Require a substantial bearer secret for every HTTP MCP connection."""
    if _transport() != "http":
        return None
    token = os.environ.get("OPNSENSE_MCP_AUTH_TOKEN", "")
    if len(token) < 32 or token != token.strip():
        raise ValueError("HTTP mode requires OPNSENSE_MCP_AUTH_TOKEN (at least 32 characters)")
    return StaticTokenVerifier(
        tokens={token: {"client_id": "openwebui", "scopes": ["opnsense:read"]}},
        required_scopes=["opnsense:read"],
    )


mcp = FastMCP("opnsense", version=__version__, lifespan=app_lifespan, auth=_http_auth())


@mcp.tool()
async def opn_list_targets(ctx: Context) -> dict[str, list[str]]:
    """List configured OPNsense site names without revealing URLs or credentials."""
    targets: TargetRegistry = ctx.lifespan_context["targets"]
    return {"sites": targets.names}


def get_api(ctx: Context, site: str = "") -> OPNsenseAPI:
    """Extract the OPNsense API client from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The OPNsenseAPI client instance.

    Raises:
        RuntimeError: If the API client is not initialized.
    """
    if "targets" in ctx.lifespan_context:
        return ctx.lifespan_context["targets"].resolve(site).api
    api: Any = ctx.lifespan_context.get("api")
    if not isinstance(api, OPNsenseAPI):
        msg = "OPNsense API client not initialized"
        raise RuntimeError(msg)
    return api


def get_config_cache(ctx: Context, site: str = "") -> ConfigCache:
    """Extract the ConfigCache from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The ConfigCache instance.

    Raises:
        RuntimeError: If the config cache is not initialized.
    """
    if "targets" in ctx.lifespan_context:
        return ctx.lifespan_context["targets"].resolve(site).config_cache
    cache: Any = ctx.lifespan_context.get("config_cache")
    if not isinstance(cache, ConfigCache):
        msg = "Config cache not initialized"
        raise RuntimeError(msg)
    return cache


def get_savepoint_manager(ctx: Context, site: str = "") -> SavepointManager:
    """Extract the SavepointManager from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The SavepointManager instance.

    Raises:
        RuntimeError: If the savepoint manager is not initialized.
    """
    if "targets" in ctx.lifespan_context:
        return ctx.lifespan_context["targets"].resolve(site).savepoint_mgr
    mgr: Any = ctx.lifespan_context.get("savepoint_mgr")
    if not isinstance(mgr, SavepointManager):
        msg = "Savepoint manager not initialized"
        raise RuntimeError(msg)
    return mgr


# Import tool modules to register their @mcp.tool() decorators.
from opnsense_mcp.tools import (  # noqa: E402
    dhcp,  # noqa: F401
    diagnostics,  # noqa: F401
    dns,  # noqa: F401
    firewall,  # noqa: F401
    haproxy,  # noqa: F401
    network,  # noqa: F401
    security,  # noqa: F401
    services,  # noqa: F401
    system,  # noqa: F401
    vpn,  # noqa: F401
)


def main() -> None:
    """Entry point for the OPNsense MCP server."""
    if _transport() == "stdio":
        mcp.run(transport="stdio")
        return

    host = os.environ.get("OPNSENSE_MCP_HOST", "0.0.0.0").strip()
    if not host:
        raise ValueError("OPNSENSE_MCP_HOST must not be empty")
    try:
        port = int(os.environ.get("OPNSENSE_MCP_PORT", "8000"))
    except ValueError as exc:
        raise ValueError("OPNSENSE_MCP_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("OPNSENSE_MCP_PORT must be between 1 and 65535")
    mcp.run(transport="http", host=host, port=port, path="/mcp", stateless_http=True)


if __name__ == "__main__":
    main()
