"""Service tools — ACME, CrowdSec, Cron, Dynamic DNS."""

from __future__ import annotations

import re
from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, get_config_cache, mcp

# --- Dynamic DNS (os-ddclient, stable/26.7) ---
# Controller source: OPNsense/DynDNS/Api/{Accounts,Settings,Service}Controller.php
# Config model: OPNsense/DynDNS/DynDNS.xml. Never return credential fields.

_DDNS_ACCOUNT_PUBLIC = frozenset({
    "uuid", "enabled", "service", "description", "hostnames",
    "hostname", "protocol", "wildcard", "zone",
    "checkip", "dynipv6host", "checkip_timeout", "force_ssl", "ttl",
    "interface", "current_ip", "current_mtime", "use_interface",
})
_DDNS_GENERAL_FIELDS = frozenset({"enabled", "verbose", "allowipv6", "daemon_delay", "backend"})
_DDNS_UUID = re.compile(r"^[a-zA-Z0-9-]{1,64}$")


def _ddns_id(uuid: str) -> str:
    """Constrain path suffixes to a single item ID (no arbitrary URL traversal)."""
    if not _DDNS_UUID.fullmatch(uuid):
        raise ValueError("Invalid DDNS account identifier")
    return uuid


def _ddns_public(value: dict[str, Any]) -> dict[str, Any]:
    """Allow only non-credential fields (not username/API key or custom server URLs)."""
    return {key: val for key, val in value.items() if key in _DDNS_ACCOUNT_PUBLIC}


def _ddns_state(value: Any) -> str:
    """Normalize OPNsense form values for an idempotent enable/disable check."""
    if isinstance(value, dict):
        value = value.get("value", "")
    return str(value).strip().lower()


def _ddns_result(value: dict[str, Any], *, field: str = "result") -> str:
    """Avoid returning untrusted nested API errors, which can echo credentials."""
    result = value.get(field, "unknown")
    return result if isinstance(result, str) else "unknown"


@mcp.tool()
async def opn_list_ddns_accounts(
    ctx: Context,
    search: str = "",
    limit: int = 50,
    site: str = "",
) -> dict[str, Any]:
    """List os-ddclient accounts and update status, without password/token fields.

    The plugin's actual model field is hostnames (plural). No secrets are
    returned, even if a future API version adds credential-shaped fields.
    """
    api = get_api(ctx, site)
    result = await api.post(
        "dyndns.accounts.search",
        {"current": 1, "rowCount": min(max(limit, 1), 500), "searchPhrase": search},
    )
    rows = result.get("rows", [])
    return {
        "rows": [_ddns_public(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else [],
        "rowCount": result.get("rowCount", 0),
    }


@mcp.tool()
async def opn_get_ddns_account(ctx: Context, uuid: str, site: str = "") -> dict[str, Any]:
    """Read a single os-ddclient account without exposing password or API tokens."""
    result = await get_api(ctx, site).get("dyndns.accounts.get_item", path_suffix=_ddns_id(uuid))
    account = result.get("account", {})
    if not isinstance(account, dict):
        raise ValueError("Unexpected DDNS account response")
    return {"uuid": uuid, "account": _ddns_public(account)}


@mcp.tool()
async def opn_add_ddns_account(
    ctx: Context,
    service: str,
    hostname: str,
    username: str = "",
    password: str = "",
    checkip: str = "web_dyndns",
    interface: str = "",
    description: str = "",
    site: str = "",
    protocol: str = "",
    server: str = "",
    zone: str = "",
    resource_id: str = "",
    ttl: int | None = None,
    dynipv6host: str = "",
    checkip_timeout: int | None = None,
    force_ssl: bool | None = None,
    wildcard: bool | None = None,
) -> dict[str, Any]:
    """Stage one new os-ddclient account; never reconfigure implicitly.

    hostname is the legacy MCP argument name; the API field is hostnames.
    The plugin supports comma-separated hostnames. service/checkip must use
    keys from the installed plugin's model, not the UI display labels.
    IPv6 methods include web_cloudflare_ipv6; general.allowipv6 is required.
    The password is write-only and is never included in the response.
    """
    if not service.strip() or not hostname.strip():
        raise ValueError("service and hostname must be non-empty")
    if checkip == "if" and not interface.strip():
        raise ValueError("interface is required when checkip='if'")
    if ttl is not None and not 1 <= ttl <= 604800:
        raise ValueError("ttl must be between 1 and 604800")
    if checkip_timeout is not None and not 10 <= checkip_timeout <= 60:
        raise ValueError("checkip_timeout must be between 10 and 60")

    api = get_api(ctx, site)
    api.require_writes()
    account = {
        "enabled": "1", "service": service, "hostnames": hostname, "checkip": checkip,
    }
    optional = {
        "username": username, "password": password, "interface": interface,
        "description": description, "protocol": protocol, "server": server,
        "zone": zone, "resourceId": resource_id, "dynipv6host": dynipv6host,
    }
    account.update({name: value for name, value in optional.items() if value})
    if ttl is not None:
        account["ttl"] = str(ttl)
    if checkip_timeout is not None:
        account["checkip_timeout"] = str(checkip_timeout)
    if force_ssl is not None:
        account["force_ssl"] = "1" if force_ssl else "0"
    if wildcard is not None:
        account["wildcard"] = "1" if wildcard else "0"

    result = await api.post("dyndns.accounts.add", {"account": account})
    get_config_cache(ctx, site).invalidate()
    return {"result": _ddns_result(result), "uuid": result.get("uuid", ""), "applied": False}


@mcp.tool()
async def opn_update_ddns_account(
    ctx: Context,
    uuid: str,
    service: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    password: str | None = None,
    checkip: str | None = None,
    interface: str | None = None,
    description: str | None = None,
    enabled: bool | None = None,
    site: str = "",
    protocol: str | None = None,
    server: str | None = None,
    zone: str | None = None,
    resource_id: str | None = None,
    ttl: int | None = None,
    dynipv6host: str | None = None,
    checkip_timeout: int | None = None,
    force_ssl: bool | None = None,
    wildcard: bool | None = None,
) -> dict[str, Any]:
    """Patch supplied fields only; the UpdateOnly password is never read back.

    Uses the OPNsense setItem API's partial update semantics. The account is
    staged and requires a separate explicit opn_reconfigure_ddclient call.
    """
    _ddns_id(uuid)
    if hostname is not None and not hostname.strip():
        raise ValueError("hostname must not be empty")
    if service is not None and not service.strip():
        raise ValueError("service must not be empty")
    if ttl is not None and not 1 <= ttl <= 604800:
        raise ValueError("ttl must be between 1 and 604800")
    if checkip_timeout is not None and not 10 <= checkip_timeout <= 60:
        raise ValueError("checkip_timeout must be between 10 and 60")
    values = {
        "service": service, "hostnames": hostname, "username": username,
        "password": password, "checkip": checkip, "interface": interface,
        "description": description, "protocol": protocol, "server": server,
        "zone": zone, "resourceId": resource_id, "dynipv6host": dynipv6host,
    }
    account = {name: value for name, value in values.items() if value is not None}
    if enabled is not None:
        account["enabled"] = "1" if enabled else "0"
    if ttl is not None:
        account["ttl"] = str(ttl)
    if checkip_timeout is not None:
        account["checkip_timeout"] = str(checkip_timeout)
    if force_ssl is not None:
        account["force_ssl"] = "1" if force_ssl else "0"
    if wildcard is not None:
        account["wildcard"] = "1" if wildcard else "0"
    if not account:
        return {"result": "unchanged", "uuid": uuid, "applied": False}
    api = get_api(ctx, site)
    api.require_writes()
    result = await api.post("dyndns.accounts.set", {"account": account}, path_suffix=uuid)
    get_config_cache(ctx, site).invalidate()
    return {"result": _ddns_result(result), "uuid": uuid, "applied": False}


@mcp.tool()
async def opn_set_ddns_account_enabled(
    ctx: Context, uuid: str, enabled: bool, site: str = "",
) -> dict[str, Any]:
    """Set account enabled/disabled idempotently, without applying the service."""
    _ddns_id(uuid)
    api = get_api(ctx, site)
    api.require_writes()
    before = await api.get("dyndns.accounts.get_item", path_suffix=uuid)
    account = before.get("account", {})
    if not isinstance(account, dict):
        raise ValueError("Unexpected DDNS account response")
    current = _ddns_state(account.get("enabled"))
    target = "1" if enabled else "0"
    if current == target:
        return {"result": "unchanged", "uuid": uuid, "enabled": enabled, "applied": False}
    if current not in {"0", "1"}:
        raise ValueError("Cannot determine current DDNS account state")
    result = await api.post("dyndns.accounts.toggle", path_suffix=f"{uuid}/{target}")
    get_config_cache(ctx, site).invalidate()
    return {
        "result": _ddns_result(result), "uuid": uuid, "enabled": enabled, "applied": False,
    }


@mcp.tool()
async def opn_delete_ddns_account(ctx: Context, uuid: str, site: str = "") -> dict[str, Any]:
    """Stage deletion of one DDNS account. Never reload the service implicitly."""
    api = get_api(ctx, site)
    api.require_writes()
    result = await api.post("dyndns.accounts.del", path_suffix=_ddns_id(uuid))
    get_config_cache(ctx, site).invalidate()
    return {"result": _ddns_result(result), "uuid": uuid, "applied": False}


@mcp.tool()
async def opn_get_ddns_settings(ctx: Context, site: str = "") -> dict[str, Any]:
    """Read global DDNS settings: enable, verbosity, IPv6, interval and backend."""
    result = await get_api(ctx, site).get("dyndns.settings.get")
    general = result.get("ddclient", {}).get("general", {})
    if not isinstance(general, dict):
        raise ValueError("Unexpected DDNS general settings response")
    return {"general": {key: value for key, value in general.items() if key in _DDNS_GENERAL_FIELDS}}


@mcp.tool()
async def opn_patch_ddns_settings(
    ctx: Context,
    enabled: bool | None = None,
    verbose: bool | None = None,
    allowipv6: bool | None = None,
    daemon_delay: int | None = None,
    backend: str | None = None,
    site: str = "",
) -> dict[str, Any]:
    """Stage DDNS general settings. Never restart/apply implicitly.

    backend is 'opnsense' for native Python or 'ddclient' for classic ddclient.
    daemon_delay is the polling interval in seconds (1..86400).
    """
    if backend is not None and backend not in {"opnsense", "ddclient"}:
        raise ValueError("backend must be 'opnsense' or 'ddclient'")
    if daemon_delay is not None and not 1 <= daemon_delay <= 86400:
        raise ValueError("daemon_delay must be between 1 and 86400")
    general = {}
    for key, value in (("enabled", enabled), ("verbose", verbose), ("allowipv6", allowipv6)):
        if value is not None:
            general[key] = "1" if value else "0"
    if daemon_delay is not None:
        general["daemon_delay"] = str(daemon_delay)
    if backend is not None:
        general["backend"] = backend
    if not general:
        return {"result": "unchanged", "applied": False}
    api = get_api(ctx, site)
    api.require_writes()
    result = await api.post("dyndns.settings.set", {"ddclient": {"general": general}})
    get_config_cache(ctx, site).invalidate()
    return {"result": _ddns_result(result), "applied": False}


@mcp.tool()
async def opn_ddns_service_status(ctx: Context, site: str = "") -> dict[str, Any]:
    """Read running status of the DDNS plugin service."""
    result = await get_api(ctx, site).get("dyndns.service.status")
    return {"status": _ddns_result(result, field="status")}


@mcp.tool()
async def opn_reconfigure_ddclient(
    ctx: Context, site: str = "", confirm: bool = False,
) -> dict[str, Any]:
    """Explicitly apply staged DDNS configuration, only with confirm=True."""
    if not confirm:
        raise ValueError("DDNS apply requires confirm=True")
    api = get_api(ctx, site)
    api.require_writes()
    result = await api.post("dyndns.service.reconfigure")
    get_config_cache(ctx, site).invalidate()
    return {"status": _ddns_result(result, field="status"), "service": "ddclient"}


@mcp.tool()
async def opn_ddns_service_control(
    ctx: Context, action: str, confirm: bool = False, site: str = "",
) -> dict[str, Any]:
    """Explicitly start/stop/restart DDNS; operations affect the live service."""
    if action not in {"start", "stop", "restart"}:
        raise ValueError("action must be start, stop or restart")
    if not confirm:
        raise ValueError("DDNS service control requires confirm=True")
    api = get_api(ctx, site)
    api.require_writes()
    if action == "start":
        result = await api.post("dyndns.service.start")
    elif action == "stop":
        result = await api.post("dyndns.service.stop")
    else:
        result = await api.post("dyndns.service.restart")
    get_config_cache(ctx, site).invalidate()
    return {"action": action, "status": _ddns_result(result, field="status")}


@mcp.tool()
async def opn_force_refresh_ddns_accounts(
    ctx: Context, uuids: str, confirm: bool = False, site: str = "",
) -> dict[str, Any]:
    """Force refresh selected accounts with native backend (stop/reset/start).

    This is disruptive and not a read-only diagnostic. Requires explicit
    confirmation and configured native backend; it may update public DNS.
    """
    items = [item.strip() for item in uuids.split(",") if item.strip()]
    if not items or len(items) > 30 or len(items) != len(set(items)):
        raise ValueError("Provide 1..30 unique DDNS account UUIDs")
    for item in items:
        _ddns_id(item)
    if not confirm:
        raise ValueError("Force refresh requires confirm=True")
    api = get_api(ctx, site)
    api.require_writes()
    settings = await api.get("dyndns.settings.get")
    general = settings.get("ddclient", {}).get("general", {})
    if not isinstance(general, dict) or _ddns_state(general.get("enabled")) != "1":
        raise ValueError("DDNS must be enabled for force refresh")
    if _ddns_state(general.get("backend")) != "opnsense":
        raise ValueError("Force refresh requires the native opnsense backend")
    result = await api.post("dyndns.accounts.force_refresh", path_suffix=",".join(items))
    return {"status": _ddns_result(result, field="status"), "requested_accounts": len(items)}


@mcp.tool()
async def opn_list_acme_certs(
    ctx: Context,
    search: str = "",
    limit: int = 50,
    site: str = "",
) -> dict[str, Any]:
    """List ACME (Let's Encrypt) certificates and their status.

    Use this when you need to check certificate expiry dates, renewal status,
    or which domains have ACME certificates configured.
    Note: Requires the ACME client plugin (os-acme-client).
    Returns: dict with 'rows' (list of certificates) and 'rowCount' (total).
    """
    api = get_api(ctx, site)
    return await api.post(
        "acmeclient.certs.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_list_cron_jobs(
    ctx: Context,
    search: str = "",
    limit: int = 50,
    site: str = "",
) -> dict[str, Any]:
    """List scheduled cron jobs configured in OPNsense.

    Use this when you need to check what scheduled tasks are configured,
    their frequency, or which commands they run.
    Returns: dict with 'rows' (list of cron jobs) and 'rowCount' (total).
    """
    api = get_api(ctx, site)
    return await api.post(
        "cron.search_jobs",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


@mcp.tool()
async def opn_crowdsec_status(ctx: Context, site: str = "") -> dict[str, Any]:
    """Get CrowdSec security engine status and active decisions summary.

    Use this when you need to check if CrowdSec is running, see how many
    active security decisions (bans/captchas) are in effect, and get a
    quick overview of the threat protection state.
    Note: Requires the CrowdSec plugin (os-crowdsec).
    Returns: dict with 'service_status', 'decisions_count', and 'alerts_count'.
    """
    api = get_api(ctx, site)
    _search = {"current": 1, "rowCount": 500, "searchPhrase": ""}
    status = await api.get("crowdsec.service.status")
    decisions = await api.post("crowdsec.decisions.search", _search)
    alerts = await api.post("crowdsec.alerts.search", _search)

    decision_rows: list[dict[str, Any]] = decisions.get("rows", [])
    alert_rows: list[dict[str, Any]] = alerts.get("rows", [])

    return {
        "service_status": status.get("status", "unknown"),
        "decisions_count": len(decision_rows),
        "alerts_count": len(alert_rows),
        "decisions": decision_rows[:20],
        "alerts": alert_rows[:20],
    }


@mcp.tool()
async def opn_crowdsec_alerts(
    ctx: Context,
    search: str = "",
    limit: int = 50,
    site: str = "",
) -> dict[str, Any]:
    """List CrowdSec security alerts (detected threats and attacks).

    Use this when you need to review security events detected by CrowdSec,
    including brute-force attempts, port scans, and other threats.
    Note: Requires the CrowdSec plugin (os-crowdsec).
    Returns: dict with 'rows' (list of alerts) and 'rowCount' (total).
    """
    api = get_api(ctx, site)
    return await api.post(
        "crowdsec.alerts.search",
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )


# --- mDNS Repeater ---


@mcp.tool()
async def opn_mdns_repeater_status(ctx: Context, site: str = "") -> dict[str, Any]:
    """Get mDNS Repeater service status and configuration.

    Use this to check if the mDNS Repeater is installed, enabled, running,
    and which interfaces it is configured to relay multicast DNS between.

    The mDNS Repeater relays mDNS (224.0.0.251:5353) packets between selected
    interfaces, enabling device discovery (HomeKit, Chromecast, AirPlay, etc.)
    across VLANs.

    Note: Requires the mDNS Repeater plugin (os-mdns-repeater).
    Returns: dict with 'service_running', 'enabled', 'interfaces', 'blocklist'.
    """
    api = get_api(ctx, site)
    settings = await api.get("mdnsrepeater.settings.get")
    status = await api.get("mdnsrepeater.service.status")

    mdns_cfg = settings.get("mdnsrepeater", settings)
    return {
        "service_running": status.get("status", "unknown"),
        "enabled": mdns_cfg.get("enabled", "0"),
        "interfaces": mdns_cfg.get("interfaces", ""),
        "blocklist": mdns_cfg.get("blocklist", ""),
        "enable_carp": mdns_cfg.get("enablecarp", "0"),
    }


@mcp.tool()
async def opn_configure_mdns_repeater(
    ctx: Context,
    enabled: bool = True,
    interfaces: str = "lan",
    site: str = "",
) -> dict[str, Any]:
    """Enable and configure the mDNS Repeater to relay multicast DNS between interfaces.

    Use this to set up cross-VLAN mDNS discovery. The repeater relays mDNS
    packets (224.0.0.251:5353) between selected interfaces, enabling HomeKit,
    Chromecast, AirPlay, and other mDNS-based device discovery across VLANs.

    Args:
        enabled: Whether to enable the mDNS Repeater service.
        interfaces: Comma-separated list of interface names to relay between
                    (e.g. 'lan,opt1'). Minimum 2 interfaces required for
                    cross-VLAN relay. Maximum 5 interfaces supported.

    Note: Requires the mDNS Repeater plugin (os-mdns-repeater) to be installed.
    Returns: dict with 'result' and 'reconfigure_status'.
    """
    api = get_api(ctx, site)
    api.require_writes()

    settings_payload = {
        "mdnsrepeater": {
            "enabled": "1" if enabled else "0",
            "interfaces": interfaces,
        },
    }
    set_result = await api.post("mdnsrepeater.settings.set", settings_payload)
    reconfigure_result = await api.post("mdnsrepeater.service.reconfigure")
    get_config_cache(ctx, site).invalidate()

    return {
        "result": set_result.get("result", "unknown"),
        "reconfigure_status": reconfigure_result.get("status", "unknown"),
        "enabled": "1" if enabled else "0",
        "interfaces": interfaces,
    }
