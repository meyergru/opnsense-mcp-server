"""System tools — status, firmware, services, gateways, config backup, config scan."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Any

from fastmcp import Context

from opnsense_mcp import __version__
from opnsense_mcp.config_cache import is_sensitive_tag, xml_local_name
from opnsense_mcp.server import get_api, get_config_cache, get_savepoint_manager, mcp
from opnsense_mcp.tool_types import RequiredSiteName, SiteName

_SENSITIVE_GATE_ERROR = {
    "error": (
        "include_sensitive=true requires OPNSENSE_MCP_ALLOW_SENSITIVE=true in the "
        "server environment. Without it, sensitive values remain redacted."
    ),
    "error_type": "sensitive_disabled",
}


def _raw_config_export_blocked() -> bool:
    """Do not expose unconstrained config.xml sections over remote MCP."""
    return os.environ.get("OPNSENSE_MCP_TRANSPORT", "stdio").strip().lower() == "http"


_SECRET_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
    }
)


def _mask_header_value(elem: ET.Element) -> None:
    """Cover name/value HTTP-header forms without blanking benign headers."""
    if "header" not in xml_local_name(elem.tag):
        return
    attrs = {xml_local_name(key): value for key, value in elem.attrib.items()}
    name = attrs.get("name") or attrs.get("headername")
    if not name:
        for child in elem:
            if xml_local_name(child.tag) in {"name", "headername"}:
                name = child.text
                break
    if not name or name.strip().lower() not in _SECRET_HEADER_NAMES:
        return
    for key in elem.attrib:
        if xml_local_name(key) == "value":
            elem.attrib[key] = "[REDACTED]"
    for child in elem:
        if xml_local_name(child.tag) in {"value", "headervalue"}:
            child.clear()
            child.text = "[REDACTED]"
    if not len(elem) and elem.text and elem.text.strip():
        elem.text = "[REDACTED]"


def _strip_sensitive_data(xml_text: str) -> str | None:
    """Redact XML credential values, including attributes and namespaces.

    Keep non-secret configuration details usable. This is credential
    redaction, not complete anonymization of IPs, names and identifiers.
    """
    try:
        # Source is trusted (OPNsense API response), not user input
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError:
        return None

    for elem in root.iter():
        if is_sensitive_tag(elem.tag):
            # Never leave children or attributes of secret-bearing containers.
            elem.clear()
            elem.text = "[REDACTED]"
            continue
        _mask_header_value(elem)
        for key in elem.attrib:
            if is_sensitive_tag(key):
                elem.attrib[key] = "[REDACTED]"

    return ET.tostring(root, encoding="unicode", xml_declaration=True)


@mcp.tool()
async def opn_system_status(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Get OPNsense system status including firmware version and product info.

    Use this when you need to check the current firmware version, system name,
    or verify the OPNsense appliance is reachable and responding.
    Returns: dict with firmware/product info. On OPNsense 26.x+, product fields
    are nested under a 'product' key; earlier versions have them at the top level.

    Args:
        site: Exact configured site alias from opn_list_targets. Empty selects a site only in a single-target
            deployment. Optional (default: "").
    """
    api = get_api(ctx, site)
    return await api.get("firmware.status")


@mcp.tool()
async def opn_check_firmware_updates(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Check OPNsense firmware repositories for available updates without installing any.

    This explicitly calls POST /api/core/firmware/status, unlike the cached
    GET used by opn_system_status. OPNsense runs a synchronous firmware probe
    and returns its refreshed status and available package updates.

    The check contacts the configured firmware mirrors and updates local
    update-check metadata on OPNsense. It does NOT install packages, apply
    configuration changes, or reboot. The API call may take several seconds.

    Args:
        site: Exact configured site alias from opn_list_targets. Empty selects a site only in a single-target
            deployment. Optional (default: "").
    """
    api = get_api(ctx, site)
    return await api.post("firmware.status")


@mcp.tool()
async def opn_list_services(
    ctx: Context,
    search: str = "",
    limit: int = 50,
    site: SiteName = "",
) -> dict[str, Any]:
    """List system services and their running status.

    BACKEND SELECTION: A service being installed, listed or running
    does not prove it serves the requested function, interface,
    clients or traffic path. Different backends can coexist
    (Kea/ISC/dnsmasq DHCP, radvd/dnsmasq RAs, Unbound/dnsmasq DNS,
    HAProxy/Nginx/Caddy proxy chains). Correlate service status
    with configuration, listeners and the relevant interface/role.

    Use this when you need to check which services are running, stopped, or
    available on the OPNsense instance.
    Returns: dict with 'rows' (list of services) and 'rowCount' (total).

    Args:
        search: Optional search/filter phrase; empty returns results without additional filtering. Optional
            (default: "").
        limit: Maximum requested entry count; the server may impose a stricter cap. Optional (default: 50).
        site: Exact configured site alias from opn_list_targets. Empty selects a site only in a single-target
            deployment. Optional (default: "").
    """
    api = get_api(ctx, site)
    return await api.post(
        "core.service.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_gateway_status(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Get gateway status including dpinger health checks.

    Use this when you need to check if WAN gateways are up, their latency,
    packet loss, or failover state.
    Returns: dict with gateway items including status, loss, and delay fields.

    Args:
        site: Exact configured site alias from opn_list_targets. Empty selects a site only in a single-target
            deployment. Optional (default: "").
    """
    api = get_api(ctx, site)
    return await api.get("gateway.status")


@mcp.tool()
async def opn_download_config(
    ctx: Context,
    include_sensitive: bool = False,
    site: SiteName = "",
) -> dict[str, Any]:
    """Download OPNsense config.xml backup as raw XML.

    Use this ONLY when you need a full XML backup for archival purposes.
    For analyzing specific config sections, use opn_scan_config to build a
    cached inventory, then opn_get_config_section to query individual sections.

    By default, sensitive data (passwords, keys, secrets) is redacted.
    include_sensitive=true requires OPNSENSE_MCP_ALLOW_SENSITIVE=true.
    Returns: dict with 'config_xml' (str), 'stripped' (bool), 'size_bytes' (int).

    Args:
        include_sensitive: Request unredacted credentials; unavailable for remote HTTP MCP even when true.
            Optional (default: False).
        site: Exact configured site alias from opn_list_targets. Empty selects a site only in a single-target
            deployment. Optional (default: "").
    """
    if _raw_config_export_blocked():
        return {"error": "Raw configuration export is disabled for remote MCP clients"}
    api = get_api(ctx, site)
    if include_sensitive and not api._config.allow_sensitive:
        return dict(_SENSITIVE_GATE_ERROR)

    xml_text = await api.get_text("core.backup.download")

    if not include_sensitive:
        stripped = _strip_sensitive_data(xml_text)
        if stripped is None:
            return {
                "error": "config.xml could not be parsed, so it cannot be redacted; refusing to return it.",
                "error_type": "unparseable_config",
            }
        xml_text = stripped

    return {
        "config_xml": xml_text,
        "stripped": not include_sensitive,
        "size_bytes": len(xml_text),
    }


@mcp.tool()
async def opn_scan_config(ctx: Context, force: bool = False, site: SiteName = "") -> dict[str, Any]:
    """Scan the OPNsense configuration and build a cached inventory.

    BACKEND SELECTION: The returned dhcp.active is a SITE-LEVEL
    heuristic, not an authoritative DHCP/RA ownership map.
    Different DHCP servers may serve different interfaces or
    IP families. Installed and cached configurations can be
    inactive; DHCP leases and reservations may be stale.
    Verify actual per-interface roles with service status and
    domain-specific settings before any changes or conclusions.
    DNS and proxy services may also coexist or be chained.

    Use this FIRST when starting a new session. Downloads the full config,
    parses it into queryable sections, and detects runtime state (services,
    DHCP backend, DNS servers). Results are cached for the session — subsequent
    calls return the cached version unless force=True.

    Call with force=True to rescan after manual config changes on the firewall.
    Use opn_get_config_section(section) to drill into specific sections.

    Returns: dict with 'firmware', 'plugins', 'dhcp', 'dns', 'interfaces',
    'services', and 'config_sections' (list of available sections with sizes).

    Args:
        force: Re-download configuration XML and refresh the cached inventory when true; false uses an existing non-stale cache (default: False).
        site: Exact configured site alias from opn_list_targets. Empty selects a site only in a single-target
            deployment. Optional (default: "").
    """
    api = get_api(ctx, site)
    cache = get_config_cache(ctx, site)
    return await cache.load(api, force=force)


@mcp.tool()
async def opn_get_config_section(
    ctx: Context,
    section: str,
    include_sensitive: bool = False,
    site: SiteName = "",
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

    Sensitive values are redacted by default; include_sensitive=true requires
    OPNSENSE_MCP_ALLOW_SENSITIVE=true in the server environment.
    Returns: dict with 'section' name and 'data' (structured config data).

    Args:
        section: Exact configuration section from opn_scan_config's config_sections list, e.g. system, interfaces, filter or nat. Required.
        include_sensitive: Request unredacted credentials; unavailable for remote HTTP MCP even when true.
            Optional (default: False).
        site: Exact configured site alias from opn_list_targets. Empty selects a site only in a single-target
            deployment. Optional (default: "").
    """
    if _raw_config_export_blocked():
        return {"error": "Raw configuration sections are disabled for remote MCP clients"}
    api = get_api(ctx, site)
    if include_sensitive and not api._config.allow_sensitive:
        return dict(_SENSITIVE_GATE_ERROR)

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
async def opn_mcp_info(ctx: Context, site: RequiredSiteName) -> dict[str, Any]:
    """Get read-only MCP runtime information for ONE explicitly selected OPNsense site.

    REQUIRED site: first call opn_list_targets, then pass the exact nonempty
    site alias (for example, site="opnsense.mgsoft"). Never call without site:
    it is a site-bound inspection, not a global capability discovery tool.

    Returns mcp_version (global server version); write_mode (general writes
    enabled for this site's API client); maintenance_mode (separate reviewed
    snapshot/firmware maintenance opt-in); opnsense_version (detected major.minor
    or null before version detection); api_style (current API route selection:
    camelCase or snake_case); savepoint_support (firewall *rule* savepoint
    rollback support, true/false after probing, null until probed).

    The response reads existing in-memory client state: it does not contact the
    firewall, check firmware repositories, validate PVE permissions, or test
    maintenance write capability. In particular, write_mode=false does not
    imply maintenance_mode=false. Firewall savepoints are NOT ZFS snapshots.

    Args:
        site: Required nonempty site alias from opn_list_targets; do not omit or pass an empty value. Required.
    """
    api = get_api(ctx, site)
    version = api.detected_version
    return {
        "mcp_version": __version__,
        "write_mode": api._config.allow_writes,
        "maintenance_mode": api._config.maintenance_enabled,
        "opnsense_version": f"{version[0]}.{version[1]}" if version else None,
        "api_style": "snake_case" if api._use_snake_case else "camelCase",
        "savepoint_support": get_savepoint_manager(ctx, site).supported,
    }
