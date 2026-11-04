"""Firewall 26.7 MVC operations, one resource on one OPNsense site per call.

These tools do not plan topology, change other sites, or automatically apply.
The fixed catalog prevents arbitrary path access. OPNsense itself validates
field types and constraints; the MCP layer validates identities, model fields,
write permission, and the requested effect.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid as uuidlib
from typing import Any
from weakref import WeakKeyDictionary

from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPI
from opnsense_mcp.firewall_catalog import (
    RESOURCES,
    FirewallLoggingKind,
    FirewallMoveKind,
    FirewallResource,
    FirewallResourceName,
    FirewallToggleKind,
)
from opnsense_mcp.server import get_api, get_config_cache, mcp
from opnsense_mcp.tool_types import SiteName

_FIELD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]*\Z")
_ALIAS_RE = re.compile(r"[a-zA-Z0-9_]{1,128}\Z")
_LOCKS: WeakKeyDictionary[OPNsenseAPI, asyncio.Lock] = WeakKeyDictionary()


def _kind(value: str) -> FirewallResource:
    if value not in RESOURCES:
        raise ValueError(f"Unsupported firewall resource: {value}. Valid values: {', '.join(RESOURCES)}")
    return RESOURCES[value]


def _uuid(value: str) -> str:
    try:
        return str(uuidlib.UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("A valid firewall-object UUID is required") from exc


def _lock(api: OPNsenseAPI) -> asyncio.Lock:
    lock = _LOCKS.get(api)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[api] = lock
    return lock


def _fields(data: dict[str, str]) -> dict[str, str]:
    if not isinstance(data, dict) or not data:
        raise ValueError("Nonempty firewall fields required")
    values: dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not _FIELD_RE.fullmatch(key):
            raise ValueError("Invalid firewall field name")
        if not isinstance(value, str) or len(value) > 8192:
            raise ValueError("Firewall field values must be strings of at most 8192 characters")
        values[key] = value
    return values


def _editable_model(form: dict[str, Any], resource: FirewallResource) -> dict[str, Any]:
    node = form.get(resource.field)
    if not isinstance(node, dict):
        raise ValueError("No editable MVC object found; legacy/automatic rule or invalid UUID")
    if str(node.get("legacy", "")).lower() in {"1", "true"}:
        raise ValueError("Legacy rule cannot be modified via the MVC API")
    if str(node.get("automatic", "")).lower() in {"1", "true"}:
        raise ValueError("Automatically generated rule cannot be modified via the MVC API")
    return node


def _checked(model: dict[str, Any], data: dict[str, str]) -> None:
    unsupported = set(data) - set(model)
    if unsupported:
        raise ValueError(f"Unsupported fields for this controller: {', '.join(sorted(unsupported))}")


async def _get(api: OPNsenseAPI, kind: str, identity: str) -> dict[str, Any]:
    _kind(kind)
    return await api.get(f"fw26.{kind}.get", path_suffix=_uuid(identity))


@mcp.tool()
async def opn_firewall_list_objects(
    ctx: Context, kind: FirewallResourceName, site: SiteName = "", search: str = "", limit: int = 100
) -> dict[str, Any]:
    """List filter, dnat, snat, one_to_one, npt, alias, category or group objects.

    Valid kind values: filter, dnat, snat, one_to_one, npt, alias, category, group. 'search' is a text filter. Use the returned UUID for read/edit operations.

    For filter rules on 26.7, the backend can include legacy/non-MVC entries;
    they are searchable but not editable through the MVC CRUD endpoints.
    Search results may include automatically generated NAT rules as well.
    """
    _kind(kind)
    if not 1 <= limit <= 500 or len(search) > 512:
        raise ValueError("limit must be 1..500; search at most 512 characters")
    return await get_api(ctx, site).post(
        f"fw26.{kind}.search", {"current": 1, "rowCount": limit, "searchPhrase": search}
    )


@mcp.tool()
async def opn_firewall_get_object(ctx: Context, kind: FirewallResourceName, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Read one editable firewall configuration object by UUID; does not mutate."""

    Valid kind values: filter, dnat, snat, one_to_one, npt, alias, category, group. Read this object's model fields before a targeted patch. 'uuid' is an object UUID.
    return await _get(get_api(ctx, site), kind, uuid)


@mcp.tool()
async def opn_firewall_create_object(ctx: Context, kind: FirewallResourceName, fields: dict[str, str], site: SiteName = "") -> dict[str, Any]:
    """Create one MVC firewall object with model-validated fields; NO automatic apply."""

    Valid kind values: filter, dnat, snat, one_to_one, npt, alias, category, group. 'fields' is a mapping from exact installed MVC field names to strings; unknown fields are rejected. Consult existing objects and the target's model rather than guessing fields.
    resource = _kind(kind)
    api = get_api(ctx, site)
    api.require_writes()
    values = _fields(fields)
    template = await api.get(f"fw26.{kind}.get")
    _checked(_editable_model(template, resource), values)
    result = await api.post(f"fw26.{kind}.add", {resource.field: values})
    return {"kind": kind, "result": result, "applied": False}


@mcp.tool()
async def opn_firewall_patch_object(
    ctx: Context, kind: FirewallResourceName, uuid: str, changes: dict[str, str], site: SiteName = ""
) -> dict[str, Any]:
    """Read-before-write patch one existing MVC firewall object; no automatic apply.

    Valid kind values: filter, dnat, snat, one_to_one, npt, alias, category, group. 'changes' maps exact field names from opn_firewall_get_object for the same kind/UUID to string values. A separate opn_firewall_apply_changes(confirm=true) is needed.

    Only explicit fields are sent; OPNsense setBase merges supplied nodes,
    preserving fields not requested. Reject unknown fields and legacy entries.
    A concurrent change from outside the MCP server may still race this read.
    """
    resource = _kind(kind)
    values = _fields(changes)
    api = get_api(ctx, site)
    api.require_writes()
    identity = _uuid(uuid)
    async with _lock(api):
        current = await _get(api, kind, identity)
        _checked(_editable_model(current, resource), values)
        result = await api.post(f"fw26.{kind}.set", {resource.field: values}, path_suffix=identity)
    return {"kind": kind, "uuid": identity, "changed_fields": sorted(values), "result": result, "applied": False}


@mcp.tool()
async def opn_firewall_delete_object(ctx: Context, kind: FirewallResourceName, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Delete one explicitly identified MVC rule, alias, category or group; no apply.

    Valid kind values: filter, dnat, snat, one_to_one, npt, alias, category, group. Obtain the UUID via opn_firewall_list_objects; deletion is staged, not applied.

    OPNsense performs reference checks for aliases, categories and groups.
    """
    resource = _kind(kind)
    api = get_api(ctx, site)
    api.require_writes()
    identity = _uuid(uuid)
    async with _lock(api):
        current = await _get(api, kind, identity)
        _editable_model(current, resource)
        result = await api.post(f"fw26.{kind}.del", path_suffix=identity)
    return {"kind": kind, "uuid": identity, "result": result, "applied": False}


@mcp.tool()
async def opn_firewall_set_enabled(ctx: Context, kind: FirewallToggleKind, uuid: str, enabled: bool, site: SiteName = "") -> dict[str, Any]:
    """Set enabled status of one rule or alias, not toggle blindly; no apply.

    Only kind values supporting enable/disable: filter, dnat, snat, one_to_one, npt, alias. 'enabled' is the desired Boolean state (not a toggle request); no automatic apply.

    DNAT's argument is 'disabled' and is therefore inverted; other rule
    controllers accept 'enabled'. Supplying 0/1 makes retries idempotent.
    """
    resource = _kind(kind)
    if not resource.toggle:
        raise ValueError(f"Firewall resource {kind} has no enable/disable API")
    api = get_api(ctx, site)
    api.require_writes()
    identity = _uuid(uuid)
    async with _lock(api):
        _editable_model(await _get(api, kind, identity), resource)
        desired = int(not enabled) if resource.inverted_toggle else int(enabled)
        result = await api.post(f"fw26.{kind}.toggle", path_suffix=f"{identity}/{desired}")
    return {"kind": kind, "uuid": identity, "enabled_requested": enabled, "result": result, "applied": False}


@mcp.tool()
async def opn_firewall_set_logging(ctx: Context, kind: FirewallLoggingKind, uuid: str, enabled: bool, site: SiteName = "") -> dict[str, Any]:
    """Set logging on exactly one filter/NAT/NPT rule; no firewall apply."""

    Only kind values supporting rule logging: filter, dnat, snat, one_to_one, npt. 'enabled' is the desired Boolean state; no automatic apply.
    resource = _kind(kind)
    if not resource.logging:
        raise ValueError("Logging switch is available only for firewall/NAT/NPT rules")
    api = get_api(ctx, site)
    api.require_writes()
    identity = _uuid(uuid)
    _editable_model(await _get(api, kind, identity), resource)
    result = await api.post(f"fw26.{kind}.log", path_suffix=f"{identity}/{int(enabled)}")
    return {"kind": kind, "uuid": identity, "logging_requested": enabled, "result": result, "applied": False}


@mcp.tool()
async def opn_firewall_move_rule(
    ctx: Context, kind: FirewallMoveKind, uuids: list[str], before_uuid: str, site: SiteName = ""
) -> dict[str, Any]:
    """Move 1-50 selected MVC rules before one other rule; no apply.

    Only orderable kind values: filter, dnat, snat, one_to_one, npt. 'uuids' is a list of 1–50 distinct rule UUID strings; 'before_uuid' is the destination rule UUID. No automatic apply.

    OPNsense validates ordering and priority groups; cannot move legacy rules.
    """
    resource = _kind(kind)
    if not resource.movable:
        raise ValueError("This firewall resource does not support ordering")
    api = get_api(ctx, site)
    api.require_writes()
    selected = [_uuid(x) for x in uuids]
    target = _uuid(before_uuid)
    if not 1 <= len(selected) <= 50 or len(set(selected)) != len(selected) or target in selected:
        raise ValueError("Select 1-50 distinct rules, excluding the destination UUID")
    # Ensure all source and destination rules are MVC objects.
    for identity in [*selected, target]:
        _editable_model(await _get(api, kind, identity), resource)
    result = await api.post(f"fw26.{kind}.move", path_suffix=f"{','.join(selected)}/{target}")
    return {"kind": kind, "moved": selected, "before": target, "result": result, "applied": False}


@mcp.tool()
async def opn_firewall_apply_changes(ctx: Context, site: SiteName = "", confirm: bool = False) -> dict[str, Any]:
    """EXPLICITLY reload firewall configuration; may interrupt remote management.

    No 60-second savepoint rollback exists on OPNsense 26.7+. Requires
    site's write permission AND confirm=true. This is deliberately separate
    from every create/patch/delete/toggle/move operation.
    """
    api = get_api(ctx, site)
    api.require_writes()
    if not confirm:
        return {"error": "Set confirm=true to apply firewall changes; no automatic rollback on 26.7+"}
    result = await api.post("fw26.filter.apply")
    get_config_cache(ctx, site).invalidate()
    return {"result": result, "applied": True, "rollback_guaranteed": False}


@mcp.tool()
async def opn_firewall_get_source_nat_settings(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Read 26.7 Source NAT general mode/settings; not the list of SNAT rules."""
    return await get_api(ctx, site).get("fw26.source_nat.get_settings")


@mcp.tool()
async def opn_firewall_patch_source_nat_settings(
    ctx: Context, changes: dict[str, str], site: SiteName = ""
) -> dict[str, Any]:
    """Patch Source NAT general settings after verifying the 26.7 schema; no apply."""
    values = _fields(changes)
    api = get_api(ctx, site)
    api.require_writes()
    async with _lock(api):
        before = await api.get("fw26.source_nat.get_settings")
        general = before.get("filter", {}).get("general")
        if not isinstance(general, dict):
            raise ValueError("Source NAT general settings are unavailable")
        _checked(general, values)
        result = await api.post("fw26.source_nat.set_settings", {"filter": {"general": values}})
    return {"result": result, "applied": False}


@mcp.tool()
async def opn_firewall_get_rule_stats(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Read live per-rule packet/byte counters from pf."""
    return await get_api(ctx, site).get("fw26.filter.rule_stats")


@mcp.tool()
async def opn_firewall_get_interface_options(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Read interface/group selectors used by Firewall 26.7 rules."""
    return await get_api(ctx, site).get("fw26.filter.get_interfaces")


@mcp.tool()
async def opn_firewall_alias_references(ctx: Context, ip: str, site: SiteName = "") -> dict[str, Any]:
    """Find aliases referencing a literal IPv4/IPv6 address or network."""
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError as exc:
        raise ValueError("A valid literal IP address or prefix is required") from exc
    return await get_api(ctx, site).post("fw26.alias.references", {"ip": ip})


@mcp.tool()
async def opn_firewall_list_alias_table(ctx: Context, alias: str, site: SiteName = "") -> dict[str, Any]:
    """Read resolved IP/table contents of one named firewall alias."""
    if not _ALIAS_RE.fullmatch(alias):
        raise ValueError("Invalid alias name")
    return await get_api(ctx, site).get("fw26.alias.table_contents", path_suffix=alias)


@mcp.tool()
async def opn_firewall_legacy_rule_counts(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Read counts of old legacy firewall and outbound NAT rules; no migration."""
    api = get_api(ctx, site)
    return {
        "legacy_rules": await api.get("fw26.migration.count_rules"),
        "legacy_outbound_nat": await api.get("fw26.migration.count_outbound"),
    }


@mcp.tool()
async def opn_firewall_reconfigure_aliases(ctx: Context, site: SiteName = "", confirm: bool = False) -> dict[str, Any]:
    """Explicitly refresh aliases after changes; may refresh firewall tables."""
    api = get_api(ctx, site)
    api.require_writes()
    if not confirm:
        return {"error": "Explicit confirm=true required to refresh aliases"}
    return {"result": await api.post("fw26.alias.reconfigure")}


@mcp.tool()
async def opn_firewall_reconfigure_groups(ctx: Context, site: SiteName = "", confirm: bool = False) -> dict[str, Any]:
    """Explicitly reconfigure firewall interface groups; may affect traffic."""
    api = get_api(ctx, site)
    api.require_writes()
    if not confirm:
        return {"error": "Explicit confirm=true required to reconfigure interface groups"}
    return {"result": await api.post("fw26.group.reconfigure")}
