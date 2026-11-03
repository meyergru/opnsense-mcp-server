"""System tools — status, firmware, services, gateways, config backup, config scan."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Any

from fastmcp import Context

from opnsense_mcp import __version__
from opnsense_mcp.config_cache import SENSITIVE_TAGS
from opnsense_mcp.server import get_api, get_config_cache, get_savepoint_manager, mcp


def _raw_config_export_blocked() -> bool:
    """Do not expose unconstrained config.xml sections over remote MCP."""
    return os.environ.get("OPNSENSE_MCP_TRANSPORT", "stdio").strip().lower() == "http"


def _strip_sensitive_data(xml_text: str) -> str:
    """Replace sensitive element text with [REDACTED] in config XML."""
    try:
        # Source is trusted (OPNsense API response), not user input
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError:
        return xml_text

    for elem in root.iter():
        if elem.tag.lower() in SENSITIVE_TAGS and elem.text:
            elem.text = "[REDACTED]"

    return ET.tostring(root, encoding="unicode", xml_declaration=True)


@mcp.tool()
async def opn_system_status(ctx: Context, site: str = "") -> dict[str, Any]:
    """Get OPNsense system status including firmware version and product info.

    Use this when you need to check the current firmware version, system name,
    or verify the OPNsense appliance is reachable and responding.
    Returns: dict with firmware/product info. On OPNsense 26.x+, product fields
    are nested under a 'product' key; earlier versions have them at the top level.
    """
    api = get_api(ctx, site)
    return await api.get("firmware.status")


@mcp.tool()
async def opn_check_firmware_updates(ctx: Context, site: str = "") -> dict[str, Any]:
    """Check OPNsense firmware repositories for available updates without installing any.

    This explicitly calls POST /api/core/firmware/status, unlike the cached
    GET used by opn_system_status. OPNsense runs a synchronous firmware probe
    and returns its refreshed status and available package updates.

    The check contacts the configured firmware mirrors and updates local
    update-check metadata on OPNsense. It does NOT install packages, apply
    configuration changes, or reboot. The API call may take several seconds.
    """
    api = get_api(ctx, site)
    return await api.post("firmware.status")


@mcp.tool()
async def opn_list_services(
    ctx: Context,
    search: str = "",
    limit: int = 50,
    site: str = "",
) -> dict[str, Any]:
    """List system services and their running status.

    Use this when you need to check which services are running, stopped, or
    available on the OPNsense instance.
    Returns: dict with 'rows' (list of services) and 'rowCount' (total).
    """
    api = get_api(ctx, site)
    return await api.post(
        "core.service.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_gateway_status(ctx: Context, site: str = "") -> dict[str, Any]:
    """Get gateway status including dpinger health checks.

    Use this when you need to check if WAN gateways are up, their latency,
    packet loss, or failover state.
    Returns: dict with gateway items including status, loss, and delay fields.
    """
    api = get_api(ctx, site)
    return await api.get("gateway.status")


@mcp.tool()
async def opn_download_config(
    ctx: Context,
    include_sensitive: bool = False,
    site: str = "",
) -> dict[str, Any]:
    """Download OPNsense config.xml backup as raw XML.

    Use this ONLY when you need a full XML backup for archival purposes.
    For analyzing specific config sections, use opn_scan_config to build a
    cached inventory, then opn_get_config_section to query individual sections.

    By default, sensitive data (passwords, keys, secrets) is redacted.
    Returns: dict with 'config_xml' (str), 'stripped' (bool), 'size_bytes' (int).
    """
    if _raw_config_export_blocked():
        return {"error": "Raw configuration export is disabled for remote MCP clients"}
    api = get_api(ctx, site)
    xml_text = await api.get_text("core.backup.download")

    if not include_sensitive:
        xml_text = _strip_sensitive_data(xml_text)

    return {
        "config_xml": xml_text,
        "stripped": not include_sensitive,
        "size_bytes": len(xml_text),
    }


@mcp.tool()
async def opn_scan_config(ctx: Context, force: bool = False, site: str = "") -> dict[str, Any]:
    """Scan the OPNsense configuration and build a cached inventory.

    Use this FIRST when starting a new session. Downloads the full config,
    parses it into queryable sections, and detects runtime state (services,
    DHCP backend, DNS servers). Results are cached for the session — subsequent
    calls return the cached version unless force=True.

    Call with force=True to rescan after manual config changes on the firewall.
    Use opn_get_config_section(section) to drill into specific sections.

    Returns: dict with 'firmware', 'plugins', 'dhcp', 'dns', 'interfaces',
    'services', and 'config_sections' (list of available sections with sizes).
    """
    api = get_api(ctx, site)
    cache = get_config_cache(ctx, site)
    return await cache.load(api, force=force)


@mcp.tool()
async def opn_get_config_section(
    ctx: Context,
    section: str,
    include_sensitive: bool = False,
    site: str = "",
) -> dict[str, Any]:
    """Get a specific configuration section as structured JSON.

    Use this after opn_scan_config to drill into a specific area of the
    OPNsense configuration. If the config hasn't been scanned yet, it will
    be loaded automatically.

    Available sections vary by OPNsense installation. Common sections include:
    system, interfaces, vlans, filter (legacy firewall rules), nat, OPNsense
    (MVC plugin config), unbound, dnsmasq, dhcpd, staticroutes, syslog.

    The 'filter' section is particularly useful — it contains legacy GUI
    firewall rules that are NOT visible via opn_list_firewall_rules.

    Returns: dict with 'section' name and 'data' (structured config data).
    """
    if _raw_config_export_blocked():
        return {"error": "Raw configuration sections are disabled for remote MCP clients"}
    api = get_api(ctx, site)
    cache = get_config_cache(ctx, site)

    if not cache.is_loaded or cache.is_stale:
        await cache.load(api)

    result = cache.get_section(section, include_sensitive=include_sensitive)
    if result is None:
        return {
            "error": f"Section '{section}' not found",
            "available_sections": cache.available_sections(),
        }
    return result


@mcp.tool()
async def opn_mcp_info(ctx: Context, site: str = "") -> dict[str, Any]:
    """Get MCP server version and runtime configuration.

    Use this to check the MCP server version, whether write mode is enabled,
    the detected OPNsense API version, and whether firewall writes still get
    savepoint/rollback protection.
    Returns: dict with 'mcp_version', 'write_mode', 'opnsense_version',
    'api_style' and 'savepoint_support'. 'savepoint_support' is true when the
    60-second auto-revert is available, false when OPNsense no longer offers it
    (26.7+ removed it upstream, so firewall changes are immediate and permanent),
    and null when no firewall write has probed for it yet.
    """
    api = get_api(ctx, site)
    version = api.detected_version
    return {
        "mcp_version": __version__,
        "write_mode": api._config.allow_writes,
        "opnsense_version": f"{version[0]}.{version[1]}" if version else None,
        "api_style": "snake_case" if api._use_snake_case else "camelCase",
        "savepoint_support": get_savepoint_manager(ctx, site).supported,
    }
