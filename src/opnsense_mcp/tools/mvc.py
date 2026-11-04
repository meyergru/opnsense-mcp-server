"""Single-site OPNsense MVC object operations.

The agent plans inter-site dependencies. These tools do only local CRUD,
pre-read checks, validated patches and explicit service reconfiguration.

OPNsense setBase() updates supplied fields without replacing other fields.
For WireGuard peers its custom setClientAction() ALSO synchronises instance
membership; therefore every patch reads and preserves the 'servers' relation.
"""

from __future__ import annotations

import asyncio
import base64
import re
import secrets
import time
import uuid as uuidlib
from typing import Any
from weakref import WeakKeyDictionary

from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPI
from opnsense_mcp.mvc_catalog import GLOBAL_SETTINGS, MVCResource, RESOURCES
from opnsense_mcp.server import get_api, get_config_cache, mcp

_SECRET_FIELDS = frozenset(
    {"psk", "privkey", "privatekey", "presharedkey", "secret", "key", "password", "token", "apikey", "apisecret"}
)
_FIELD_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_]*\Z")
_PSK_REFS: dict[str, tuple[str, float]] = {}
_LOCKS: WeakKeyDictionary[OPNsenseAPI, asyncio.Lock] = WeakKeyDictionary()
_PSK_TTL = 1800


def _resource(family: str, kind: str) -> MVCResource:
    try:
        return RESOURCES[family][kind]
    except KeyError:
        raise ValueError(f"Unsupported {family} resource: {kind}") from None


def _uuid(value: str) -> str:
    try:
        return str(uuidlib.UUID(value))
    except (ValueError, AttributeError):
        raise ValueError("A valid OPNsense object UUID is required") from None


def _sanitize(value: Any) -> Any:
    """Strip confidential fields instead of allowing the global guard to reject responses."""
    if isinstance(value, dict):
        return {
            str(k): _sanitize(v)
            for k, v in value.items()
            if re.sub(r"[_\s-]", "", str(k)).lower() not in _SECRET_FIELDS
        }
    if isinstance(value, list):
        return [_sanitize(x) for x in value]
    return value


def _validated_values(data: dict[str, str]) -> dict[str, str]:
    if not isinstance(data, dict) or not data:
        raise ValueError("At least one field is required")
    result: dict[str, str] = {}
    for name, value in data.items():
        if not isinstance(name, str) or not _FIELD_NAME.fullmatch(name):
            raise ValueError("Invalid model field name")
        if name.lower() in _SECRET_FIELDS:
            raise ValueError("Pass WireGuard PSKs via a one-time psk_ref, not plaintext model values")
        if not isinstance(value, str) or len(value) > 65536:
            raise ValueError(f"Field {name} must be a string of at most 65536 characters")
        result[name] = value
    return result


def _relation(value: Any) -> str:
    """Convert OPNsense MVC ModelRelationField selected option map to CSV UUIDs."""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return ",".join(value)
    if isinstance(value, dict) and all(
        isinstance(v, dict) and "selected" in v for v in value.values()
    ):
        return ",".join(
            k for k, details in value.items() if str(details.get("selected")).lower() in {"true", "1"}
        )
    raise ValueError("Cannot safely preserve existing WireGuard instance assignments")


def _psk_from_ref(reference: str) -> str:
    entry = _PSK_REFS.get(reference)
    if entry is None or entry[1] < time.monotonic():
        raise ValueError("Unknown or expired PSK reference; generate a new one")
    return entry[0]


def _lock(api: OPNsenseAPI) -> asyncio.Lock:
    lock = _LOCKS.get(api)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[api] = lock
    return lock


async def _list(api: OPNsenseAPI, family: str, kind: str, search: str, limit: int) -> dict[str, Any]:
    resource = _resource(family, kind)
    if not 1 <= limit <= 500:
        raise ValueError("limit must be 1..500")
    result = await api.post(
        resource.logical("search"),
        {"current": 1, "rowCount": limit, "searchPhrase": search},
    )
    return _sanitize(result)


async def _get(api: OPNsenseAPI, family: str, kind: str, obj_id: str) -> dict[str, Any]:
    resource = _resource(family, kind)
    result = await api.get(resource.logical("get"), path_suffix=_uuid(obj_id))
    if not isinstance(result.get(resource.field), dict):
        raise ValueError("Object not found or its model response is unsupported")
    return {"uuid": obj_id, "fields": _sanitize(result[resource.field])}


async def _add(
    api: OPNsenseAPI, family: str, kind: str, data: dict[str, str], psk_ref: str = ""
) -> dict[str, Any]:
    resource = _resource(family, kind)
    api.require_writes()
    values = _validated_values(data)
    if family == "wireguard" and kind == "peer":
        if not values.get("servers"):
            raise ValueError("A WireGuard peer must reference an existing local instance via servers")
        # Verify local association before writes. The model chooses the remote-side sequence.
        for server_id in values["servers"].split(","):
            if not isinstance(
                (await api.get("mvc.wireguard.instance.get", path_suffix=_uuid(server_id))).get("server"),
                dict,
            ):
                raise ValueError("Selected WireGuard instance is missing")
    elif psk_ref:
        raise ValueError("A PSK reference is only valid when creating a WireGuard peer")
    if psk_ref:
        values["psk"] = _psk_from_ref(psk_ref)
    # Validate against the actual per-version MVC schema; never write arbitrary new fields.
    template = await api.get(resource.logical("get"))
    fields = template.get(resource.field)
    if not isinstance(fields, dict) or set(values) - set(fields):
        raise ValueError("Fields are not supported by this OPNsense resource model")
    result = await api.post(resource.logical("add"), {resource.field: values})
    return _sanitize(result)


async def _patch(
    api: OPNsenseAPI, family: str, kind: str, obj_id: str,
    changes: dict[str, str], psk_ref: str = ""
) -> dict[str, Any]:
    resource = _resource(family, kind)
    api.require_writes()
    values = _validated_values(changes) if changes else {}
    if psk_ref and (family, kind) != ("wireguard", "peer"):
        raise ValueError("psk_ref is valid only for WireGuard peer changes")
    if not values and not psk_ref:
        raise ValueError("No changes supplied")
    target = _uuid(obj_id)
    async with _lock(api):
        current = await api.get(resource.logical("get"), path_suffix=target)
        fields = current.get(resource.field)
        if not isinstance(fields, dict):
            raise ValueError("Object not found: refusing implicit upsert")
        if set(values) - set(fields):
            raise ValueError("Patch includes a field unsupported by the existing object")
        if (family, kind) == ("wireguard", "peer"):
            # CRITICAL: OPNsense's setClient() rewrites server.peers based on 'servers';
            # omitting it would remove the peer from all existing WG instances.
            if "servers" not in fields:
                raise ValueError("Missing existing WireGuard servers relation: refusing unsafe patch")
            if "servers" not in values:
                values["servers"] = _relation(fields["servers"])
            if psk_ref:
                values["psk"] = _psk_from_ref(psk_ref)
        elif psk_ref:
            raise ValueError("PSK reference is only valid for WireGuard peer changes")
        result = await api.post(resource.logical("set"), {resource.field: values}, path_suffix=target)
    return {"uuid": target, "result": _sanitize(result), "applied": False}


async def _delete(api: OPNsenseAPI, family: str, kind: str, obj_id: str) -> dict[str, Any]:
    resource = _resource(family, kind)
    api.require_writes()
    target = _uuid(obj_id)
    # Delete is explicit and never automatically followed by reconfigure.
    result = await api.post(resource.logical("del"), path_suffix=target)
    return {"uuid": target, "result": _sanitize(result), "applied": False}


async def _toggle(
    api: OPNsenseAPI, family: str, kind: str, obj_id: str, enabled: bool
) -> dict[str, Any]:
    resource = _resource(family, kind)
    if not resource.toggle:
        raise ValueError(f"{family}.{kind} has no toggle API")
    api.require_writes()
    target = _uuid(obj_id)
    result = await api.post(
        resource.logical("toggle"), path_suffix=f"{target}/{int(enabled)}"
    )
    return {"uuid": target, "result": _sanitize(result), "applied": False}


@mcp.tool()
async def opn_wireguard_generate_psk(ctx: Context) -> dict[str, Any]:
    """Generate a cryptographically secure PSK in server memory and return an opaque reference.

    This reference can be used separately in two peer patches, in whatever
    order the agent chooses, without returning the secret to the language model.
    It expires after 30 minutes or a container restart.
    """
    # ctx is used by MCP to bind an authenticated tool call.
    del ctx
    now = time.monotonic()
    for ref, (_, expires) in list(_PSK_REFS.items()):
        if expires < now:
            del _PSK_REFS[ref]
    reference = secrets.token_urlsafe(24)
    _PSK_REFS[reference] = (base64.b64encode(secrets.token_bytes(32)).decode("ascii"), now + _PSK_TTL)
    return {"psk_ref": reference, "expires_in_seconds": _PSK_TTL}


@mcp.tool()
async def opn_wireguard_list_peers(ctx: Context, site: str = "", search: str = "", limit: int = 100) -> dict[str, Any]:
    """List existing WireGuard peers; never expose PSKs or private keys."""
    return await _list(get_api(ctx, site), "wireguard", "peer", search, limit)


@mcp.tool()
async def opn_wireguard_get_peer(ctx: Context, uuid: str, site: str = "") -> dict[str, Any]:
    """Read a WireGuard peer's configuration with secrets stripped."""
    return await _get(get_api(ctx, site), "wireguard", "peer", uuid)


@mcp.tool()
async def opn_wireguard_add_peer(
    ctx: Context, fields: dict[str, str], site: str = "", psk_ref: str = ""
) -> dict[str, Any]:
    """Add one peer to an EXISTING local WireGuard instance; never apply automatically.

    Pass servers=<local instance UUID> and tunneladdress=<remote AllowedIPs CSV>.
    The model is responsible for selecting the other site's networks and keys.
    """
    return await _add(get_api(ctx, site), "wireguard", "peer", fields, psk_ref)


@mcp.tool()
async def opn_wireguard_patch_peer(
    ctx: Context, uuid: str, changes: dict[str, str], site: str = "", psk_ref: str = ""
) -> dict[str, Any]:
    """Read-modify-write exactly one existing peer while preserving instance assignments.

    For a PSK rotation use a previously generated psk_ref, once on each site.
    This tool does NOT select the remote/local order or apply the change.
    """
    return await _patch(get_api(ctx, site), "wireguard", "peer", uuid, changes, psk_ref)


@mcp.tool()
async def opn_wireguard_delete_peer(ctx: Context, uuid: str, site: str = "") -> dict[str, Any]:
    """Delete exactly one selected WireGuard peer; requires explicit write permissions."""
    return await _delete(get_api(ctx, site), "wireguard", "peer", uuid)


@mcp.tool()
async def opn_wireguard_list_instances(ctx: Context, site: str = "") -> dict[str, Any]:
    """List existing WireGuard instances without changing or replacing them."""
    return await _list(get_api(ctx, site), "wireguard", "instance", "", 100)


@mcp.tool()
async def opn_wireguard_get_instance(ctx: Context, uuid: str, site: str = "") -> dict[str, Any]:
    """Read a WireGuard instance, with its private key stripped."""
    return await _get(get_api(ctx, site), "wireguard", "instance", uuid)


@mcp.tool()
async def opn_wireguard_patch_instance(
    ctx: Context, uuid: str, changes: dict[str, str], site: str = ""
) -> dict[str, Any]:
    """Patch one existing WireGuard instance without touching others or applying."""
    return await _patch(get_api(ctx, site), "wireguard", "instance", uuid, changes)


@mcp.tool()
async def opn_kea_list(
    ctx: Context, resource: str, site: str = "", search: str = "", limit: int = 100
) -> dict[str, Any]:
    """List Kea DHCPv4/v6 subnets, reservations, options, PD pools or HA peers."""
    return await _list(get_api(ctx, site), "kea", resource, search, limit)


@mcp.tool()
async def opn_kea_get(ctx: Context, resource: str, uuid: str, site: str = "") -> dict[str, Any]:
    """Read one Kea DHCPv4/v6 configuration object by UUID."""
    return await _get(get_api(ctx, site), "kea", resource, uuid)


@mcp.tool()
async def opn_kea_add(ctx: Context, resource: str, fields: dict[str, str], site: str = "") -> dict[str, Any]:
    """Create one Kea object; validate fields against OPNsense MVC form, do not apply."""
    return await _add(get_api(ctx, site), "kea", resource, fields)


@mcp.tool()
async def opn_kea_patch(
    ctx: Context, resource: str, uuid: str, changes: dict[str, str], site: str = ""
) -> dict[str, Any]:
    """Read-before-write patch one Kea object; all other fields and objects unchanged."""
    return await _patch(get_api(ctx, site), "kea", resource, uuid, changes)


@mcp.tool()
async def opn_kea_delete(ctx: Context, resource: str, uuid: str, site: str = "") -> dict[str, Any]:
    """Delete one explicitly identified Kea configuration object; no apply."""
    return await _delete(get_api(ctx, site), "kea", resource, uuid)


@mcp.tool()
async def opn_radvd_list(ctx: Context, site: str = "", search: str = "") -> dict[str, Any]:
    """List radvd IPv6 Router Advertisement entries."""
    return await _list(get_api(ctx, site), "radvd", "entry", search, 100)


@mcp.tool()
async def opn_radvd_get(ctx: Context, uuid: str, site: str = "") -> dict[str, Any]:
    """Read one radvd entry."""
    return await _get(get_api(ctx, site), "radvd", "entry", uuid)


@mcp.tool()
async def opn_radvd_add(ctx: Context, fields: dict[str, str], site: str = "") -> dict[str, Any]:
    """Create one radvd entry; does not reconfigure daemon."""
    return await _add(get_api(ctx, site), "radvd", "entry", fields)


@mcp.tool()
async def opn_radvd_patch(ctx: Context, uuid: str, changes: dict[str, str], site: str = "") -> dict[str, Any]:
    """Read-before-write patch one radvd entry without affecting others."""
    return await _patch(get_api(ctx, site), "radvd", "entry", uuid, changes)


@mcp.tool()
async def opn_radvd_delete(ctx: Context, uuid: str, site: str = "") -> dict[str, Any]:
    """Delete one radvd entry without restarting radvd."""
    return await _delete(get_api(ctx, site), "radvd", "entry", uuid)


@mcp.tool()
async def opn_radvd_toggle(ctx: Context, uuid: str, enabled: bool, site: str = "") -> dict[str, Any]:
    """Enable/disable one radvd entry, no automatic reconfigure."""
    return await _toggle(get_api(ctx, site), "radvd", "entry", uuid, enabled)


@mcp.tool()
async def opn_unbound_list(
    ctx: Context, resource: str, site: str = "", search: str = "", limit: int = 100
) -> dict[str, Any]:
    """List Unbound host overrides, forwards, host aliases, ACLs or DNSBL objects."""
    return await _list(get_api(ctx, site), "unbound", resource, search, limit)


@mcp.tool()
async def opn_unbound_get(ctx: Context, resource: str, uuid: str, site: str = "") -> dict[str, Any]:
    """Read one Unbound configuration object with secrets removed."""
    return await _get(get_api(ctx, site), "unbound", resource, uuid)


@mcp.tool()
async def opn_unbound_add(
    ctx: Context, resource: str, fields: dict[str, str], site: str = ""
) -> dict[str, Any]:
    """Create one Unbound MVC object without restarting DNS."""
    return await _add(get_api(ctx, site), "unbound", resource, fields)


@mcp.tool()
async def opn_unbound_patch(
    ctx: Context, resource: str, uuid: str, changes: dict[str, str], site: str = ""
) -> dict[str, Any]:
    """Read-before-write patch an Unbound MVC object without modifying other records."""
    return await _patch(get_api(ctx, site), "unbound", resource, uuid, changes)


@mcp.tool()
async def opn_unbound_delete(ctx: Context, resource: str, uuid: str, site: str = "") -> dict[str, Any]:
    """Delete one Unbound MVC object; explicit apply remains separate."""
    return await _delete(get_api(ctx, site), "unbound", resource, uuid)


@mcp.tool()
async def opn_unbound_toggle(
    ctx: Context, resource: str, uuid: str, enabled: bool, site: str = ""
) -> dict[str, Any]:
    """Enable or disable one Unbound MVC object; no DNS reconfigure."""
    return await _toggle(get_api(ctx, site), "unbound", resource, uuid, enabled)


@mcp.tool()
async def opn_service_apply(ctx: Context, service: str, site: str = "") -> dict[str, Any]:
    """Explicitly apply pending WireGuard/Kea/radvd/Unbound changes on one site.

    May restart services or disrupt traffic. This is not called automatically
    by the CRUD helpers. Cross-site sequencing is the model's responsibility.
    """
    if service not in {"wireguard", "kea", "radvd", "unbound"}:
        raise ValueError("Unsupported service; choose wireguard, kea, radvd or unbound")
    api = get_api(ctx, site)
    api.require_writes()
    result = await api.post(f"mvc.service.{service}.reconfigure")
    get_config_cache(ctx, site).invalidate()
    return {"service": service, "result": _sanitize(result)}



@mcp.tool()
async def opn_kea_list_leases6(
    ctx: Context, search: str = "", limit: int = 100, site: str = ""
) -> dict[str, Any]:
    """List Kea DHCPv6 leases without modifying lease state."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be 1..500")
    result = await get_api(ctx, site).post(
        "mvc.kea.leases6.search",
        {"current": 1, "rowCount": limit, "searchPhrase": search},
    )
    return _sanitize(result)


@mcp.tool()
async def opn_kea_delete_lease(ctx: Context, ip: str, site: str = "") -> dict[str, Any]:
    """Explicitly remove a Kea lease by IP address. This does not change reservations."""
    import ipaddress

    address = str(ipaddress.ip_address(ip))
    api = get_api(ctx, site)
    api.require_writes()
    return _sanitize(await api.post("mvc.kea.leases.del", path_suffix=address))


@mcp.tool()
async def opn_mvc_get_settings(ctx: Context, subsystem: str, site: str = "") -> dict[str, Any]:
    """Read global settings of Kea DHCPv4/v6/DDNS/control-agent, radvd or Unbound."""
    if subsystem not in GLOBAL_SETTINGS:
        raise ValueError("Unsupported settings subsystem")
    _, root = GLOBAL_SETTINGS[subsystem]
    result = await get_api(ctx, site).get(f"mvc.settings.{subsystem}.get")
    return {"subsystem": subsystem, "settings": _sanitize(result.get(root, {}))}


@mcp.tool()
async def opn_mvc_patch_settings(
    ctx: Context, subsystem: str, changes: dict[str, Any], site: str = ""
) -> dict[str, Any]:
    """Patch selected global settings of one subsystem, never apply automatically.

    The OPNsense MVC base controller merges supplied nodes into existing model
    state. This first reads the installed model and refuses unknown root fields.
    Changes are restricted to pre-existing fields of the chosen settings model.
    """
    if subsystem not in GLOBAL_SETTINGS:
        raise ValueError("Unsupported settings subsystem")
    if not isinstance(changes, dict) or not changes:
        raise ValueError("Nonempty settings changes required")
    _, root = GLOBAL_SETTINGS[subsystem]
    api = get_api(ctx, site)
    api.require_writes()
    async with _lock(api):
        before = await api.get(f"mvc.settings.{subsystem}.get")
        existing = before.get(root)
        if not isinstance(existing, dict):
            raise ValueError("Global settings are unavailable; refusing write")
        if set(changes) - set(existing):
            raise ValueError("Unsupported global settings field")
        if any(re.sub(r"[_\s-]", "", str(k)).lower() in _SECRET_FIELDS for k in changes):
            raise ValueError("Do not submit secret fields from a model")
        result = await api.post(f"mvc.settings.{subsystem}.set", {root: changes})
    return {"subsystem": subsystem, "result": _sanitize(result), "applied": False}
