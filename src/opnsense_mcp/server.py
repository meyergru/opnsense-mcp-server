"""OPNsense MCP Server — FastMCP entrypoint.

Registers all tool modules and starts STDIO or authenticated Streamable HTTP.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, cast

from fastmcp import Context, FastMCP
from fastmcp.server.lifespan import lifespan
from fastmcp.server.middleware.response_limiting import ResponseLimitingMiddleware

from opnsense_mcp import __version__
from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config_cache import ConfigCache
from opnsense_mcp.secret_guard import SecretOutputGuard
from opnsense_mcp.targets import TargetRegistry
from opnsense_mcp.transport import build_auth, load_transport_config


@lifespan
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Initialize the OPNsense API client, savepoint manager, and config cache."""
    targets = TargetRegistry.from_environment()
    try:
        yield {"targets": targets}
    finally:
        await targets.close()


_transport = load_transport_config()
mcp = FastMCP("opnsense", version=__version__, lifespan=app_lifespan, auth=build_auth(_transport))
mcp.add_middleware(ResponseLimitingMiddleware(max_size=_transport.max_result_bytes))
mcp.add_middleware(SecretOutputGuard())


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
        return cast(TargetRegistry, ctx.lifespan_context["targets"]).resolve(site).api
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
        return cast(TargetRegistry, ctx.lifespan_context["targets"]).resolve(site).config_cache
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
        return cast(TargetRegistry, ctx.lifespan_context["targets"]).resolve(site).savepoint_mgr
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
    firmware,  # noqa: F401
    firmware_cve,  # noqa: F401
    haproxy,  # noqa: F401
    mvc,  # noqa: F401
    network,  # noqa: F401
    security,  # noqa: F401
    services,  # noqa: F401
    snapshots,  # noqa: F401
    system,  # noqa: F401
    vpn,  # noqa: F401
)


def main() -> None:
    """Entry point for the OPNsense MCP server."""
    if _transport.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(
            transport="http",
            host=_transport.host,
            port=_transport.port,
            path="/mcp",
            stateless_http=True,
        )


if __name__ == "__main__":
    main()
