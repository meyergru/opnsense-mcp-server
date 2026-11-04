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
from dataclasses import replace
from typing import Any, cast
from weakref import WeakKeyDictionary

from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPI
from opnsense_mcp.mvc_catalog import (
    GLOBAL_SETTINGS,
    RESOURCES,
    ApplyServiceName,
    KeaResourceName,
    MVCResource,
    SettingsSubsystemName,
    UnboundResourceName,
)
from opnsense_mcp.server import get_api, get_config_cache, mcp
from opnsense_mcp.tool_types import SiteName

_SECRET_FIELDS = frozenset(
    {"psk", "privkey", "privatekey", "presharedkey", "secret", "key", "password", "token", "apikey", "apisecret"}
)
_FIELD_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_]*\Z")
_PSK_REFS: dict[str, tuple[str, float]] = {}
_LOCKS: WeakKeyDictionary[OPNsenseAPI, asyncio.Lock] = WeakKeyDictionary()
_PSK_TTL = 1800


def _resource(family: str, kind: str) -> MVCResource:
    try:
        return replace(RESOURCES[family][kind], kind=kind)
    except KeyError:
        valid = ", ".join(RESOURCES.get(family, {}))
        raise ValueError(f"Unsupported {family} resource: {kind}. Valid values: {valid}") from None


def _uuid(value: str) -> str:
    try:
        return str(uuidlib.UUID(value))
    except (ValueError, AttributeError):
        raise ValueError("A valid OPNsense object UUID is required") from None


def _sanitize(value: Any) -> Any:  # noqa: ANN401
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


def _relation(value: Any) -> str:  # noqa: ANN401
    """Convert OPNsense MVC ModelRelationField selected option map to CSV UUIDs."""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return ",".join(value)
    if isinstance(value, dict) and all(isinstance(v, dict) and "selected" in v for v in value.values()):
        return ",".join(k for k, details in value.items() if str(details.get("selected")).lower() in {"true", "1"})
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
    return cast(dict[str, Any], _sanitize(result))


async def _get(api: OPNsenseAPI, family: str, kind: str, obj_id: str) -> dict[str, Any]:
    resource = _resource(family, kind)
    result = await api.get(resource.logical("get"), path_suffix=_uuid(obj_id))
    if not isinstance(result.get(resource.field), dict):
        raise ValueError("Object not found or its model response is unsupported")
    return {"uuid": obj_id, "fields": _sanitize(result[resource.field])}


async def _add(api: OPNsenseAPI, family: str, kind: str, data: dict[str, str], psk_ref: str = "") -> dict[str, Any]:
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
    return cast(dict[str, Any], _sanitize(result))


async def _patch(
    api: OPNsenseAPI, family: str, kind: str, obj_id: str, changes: dict[str, str], psk_ref: str = ""
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


async def _toggle(api: OPNsenseAPI, family: str, kind: str, obj_id: str, enabled: bool) -> dict[str, Any]:
    """Idempotently ensure an object is enabled or disabled.

    OPNsense MVC toggle*Action only accepts UUID and TOGGLES the state; it
    does not accept a desired 0/1 argument. Read first and call it at most
    once, avoiding accidental re-enablement after a retry.
    """
    resource = _resource(family, kind)
    if not resource.toggle:
        raise ValueError(f"{family}.{kind} has no toggle API")
    api.require_writes()
    target = _uuid(obj_id)
    async with _lock(api):
        current = await api.get(resource.logical("get"), path_suffix=target)
        form = current.get(resource.field)
        if not isinstance(form, dict):
            raise ValueError("Object not found; refusing to toggle")
        field = form.get("enabled")
        if isinstance(field, dict):
            raise ValueError("Unable to establish current enabled state from model")
        if str(field) not in {"0", "1"}:
            raise ValueError("Unable to establish current enabled state from model")
        if (str(field) == "1") == enabled:
            return {"uuid": target, "changed": False, "enabled": enabled, "applied": False}
        result = await api.post(resource.logical("toggle"), path_suffix=target)
    if result.get("result") not in ("Enabled", "Disabled"):
        return {"uuid": target, "changed": "unknown", "result": _sanitize(result), "applied": False}
    return {"uuid": target, "changed": True, "enabled": enabled, "result": _sanitize(result), "applied": False}


@mcp.tool()
async def opn_wireguard_generate_psk(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Generate a cryptographically secure PSK in server memory and return an opaque reference.

    Reuse this reference for the same PSK on both ends, without disclosing it.
    For site-to-site rotations, identify LOCAL and REMOTE by their actual
    management routes before changing anything. If uncertain whether either
    firewall is managed through the VPN being changed, ask the user first.
    Update and apply the REMOTE endpoint before the LOCAL endpoint.
    It expires after 30 minutes or a container restart.
    """
    # Resolve the selected site; no site changes are made while generating.
    get_api(ctx, site)
    now = time.monotonic()
    for ref, (_, expires) in list(_PSK_REFS.items()):
        if expires < now:
            del _PSK_REFS[ref]
    reference = secrets.token_urlsafe(24)
    _PSK_REFS[reference] = (base64.b64encode(secrets.token_bytes(32)).decode("ascii"), now + _PSK_TTL)
    return {"psk_ref": reference, "expires_in_seconds": _PSK_TTL}


@mcp.tool()
async def opn_wireguard_list_peers(ctx: Context, site: SiteName = "", search: str = "", limit: int = 100) -> dict[str, Any]:
    """List existing WireGuard peers; never expose PSKs or private keys.

    This configuration listing alone does not prove whether management
    access to a target traverses the VPN being changed. Ask the user
    before coordinated cross-site changes if the access path is unclear.
    """
    return await _list(get_api(ctx, site), "wireguard", "peer", search, limit)


@mcp.tool()
async def opn_wireguard_get_peer(ctx: Context, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Read a WireGuard peer's configuration with secrets stripped.

    Do not infer which endpoint is LOCAL/REMOTE solely from peer fields or
    site labels. Clarify the management access path before modifying a tunnel.
    """
    return await _get(get_api(ctx, site), "wireguard", "peer", uuid)


@mcp.tool()
async def opn_wireguard_add_peer(
    ctx: Context, fields: dict[str, str], site: SiteName = "", psk_ref: str = ""
) -> dict[str, Any]:
    """Add one peer to an EXISTING local WireGuard instance; never apply automatically.

    Pass servers=<local instance UUID> and tunneladdress=<remote AllowedIPs CSV>.
    The model is responsible for selecting the other site's networks and keys.
    If this is a remotely managed site-to-site tunnel, establish which side is
    REMOTE (reached through the affected VPN) and which is independently LOCAL.
    If unsure, ask the user before changes. Coordinate REMOTE before LOCAL;
    see opn_service_apply's WireGuard management-path warning.
    """
    return await _add(get_api(ctx, site), "wireguard", "peer", fields, psk_ref)


@mcp.tool()
async def opn_wireguard_patch_peer(
    ctx: Context, uuid: str, changes: dict[str, str], site: SiteName = "", psk_ref: str = ""
) -> dict[str, Any]:
    """Read-modify-write exactly one existing peer while preserving instance assignments.

    For a PSK rotation use the SAME previously generated psk_ref on each end.
    This only stages changes: it neither applies nor coordinates both sites.
    If REMOTE is accessed through the affected VPN, change/apply REMOTE first,
    then change/apply the independently reachable LOCAL side. The remote
    management connection may drop after REMOTE apply; do not check its status
    until the LOCAL side has also been corrected and applied. If the
    management path or LOCAL/REMOTE roles are unclear, ask the user first.
    """
    return await _patch(get_api(ctx, site), "wireguard", "peer", uuid, changes, psk_ref)


@mcp.tool()
async def opn_wireguard_delete_peer(ctx: Context, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Stage deletion of one WireGuard peer; requires explicit write permission.

    If this peer carries access to a REMOTE firewall, applying the deletion
    may sever management access. Establish LOCAL/REMOTE management paths
    first; if unknown, ask the user before changing anything. See
    opn_service_apply for sequencing and no-intermediate-poll guidance.
    """
    return await _delete(get_api(ctx, site), "wireguard", "peer", uuid)


@mcp.tool()
async def opn_wireguard_toggle_peer(ctx: Context, uuid: str, enabled: bool, site: SiteName = "") -> dict[str, Any]:
    """Enable/disable exactly one WireGuard peer, idempotently, without applying.

    Reads current enabled state first, then invokes OPNsense's toggleClient
    only if needed. A later explicit WireGuard reconfigure is required.
    For remotely managed VPN links, establish the LOCAL/REMOTE management
    path first (ask if unclear); apply REMOTE before LOCAL and do not poll
    unreachable REMOTE during the transition. See opn_service_apply.
    """
    return await _toggle(get_api(ctx, site), "wireguard", "peer", uuid, enabled)


@mcp.tool()
async def opn_wireguard_list_instances(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """List existing WireGuard instances without changing or replacing them.

    The list cannot establish whether management access uses a WireGuard
    tunnel. Ask the user before a cross-site change if topology is uncertain.
    """
    return await _list(get_api(ctx, site), "wireguard", "instance", "", 100)


@mcp.tool()
async def opn_wireguard_get_instance(ctx: Context, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Read a WireGuard instance, with its private key stripped.

    This does not prove whether a target's management path crosses this VPN;
    clarify LOCAL/REMOTE roles with the user before applying risky changes.
    """
    return await _get(get_api(ctx, site), "wireguard", "instance", uuid)


@mcp.tool()
async def opn_wireguard_toggle_instance(ctx: Context, uuid: str, enabled: bool, site: SiteName = "") -> dict[str, Any]:
    """Enable/disable one WireGuard instance; stage only, apply separately.

    This can affect the VPN management path after apply. Determine LOCAL and
    REMOTE from actual access topology, ask if unclear, and coordinate REMOTE
    apply before LOCAL without intermediate REMOTE status polls.
    """
    return await _toggle(get_api(ctx, site), "wireguard", "instance", uuid, enabled)


@mcp.tool()
async def opn_wireguard_patch_instance(
    ctx: Context, uuid: str, changes: dict[str, str], site: SiteName = ""
) -> dict[str, Any]:
    """Patch one existing WireGuard instance; stage only, never auto-apply.

    Changing an instance carrying access to a REMOTE firewall may cut the
    management tunnel once applied. Identify LOCAL/REMOTE (ask if uncertain),
    apply REMOTE before LOCAL, and avoid status polling REMOTE between applies.
    """
    return await _patch(get_api(ctx, site), "wireguard", "instance", uuid, changes)


@mcp.tool()
async def opn_wireguard_add_instance(ctx: Context, fields: dict[str, str], site: SiteName = "") -> dict[str, Any]:
    """Create one independent WireGuard instance; generate its keys locally in OPNsense.

    Does not modify existing WireGuard instances and does not apply changes.
    Only the newly generated PUBLIC key is included in the response.
    For any later cross-site activation affecting a management VPN, determine
    LOCAL/REMOTE via the actual access path first, ask if unclear, and apply
    REMOTE before LOCAL; see opn_service_apply for the connectivity caveat.
    """
    api = get_api(ctx, site)
    api.require_writes()
    values = _validated_values(fields)
    template = await api.get("mvc.wireguard.instance.get")
    form = template.get("server")
    if not isinstance(form, dict) or set(values) - set(form):
        raise ValueError("Unknown or unavailable WireGuard instance settings fields")
    if not values.get("name"):
        raise ValueError("WireGuard instance name is required")
    result_keys = await api.get("mvc.wireguard.instance.generate_keypair")
    if result_keys.get("status") != "ok":
        raise ValueError("WireGuard keypair generation failed")
    priv = result_keys.get("privkey")
    pub = result_keys.get("pubkey")
    if not isinstance(priv, str) or not isinstance(pub, str) or len(priv) != 44 or len(pub) != 44:
        raise ValueError("WireGuard keypair generator did not return valid key lengths")
    values["privkey"] = priv
    values["pubkey"] = pub
    result = await api.post("mvc.wireguard.instance.add", {"server": values})
    return {"result": _sanitize(result), "public_key": pub, "applied": False}


@mcp.tool()
async def opn_wireguard_delete_instance(ctx: Context, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Stage deletion of one WireGuard instance; no implicit reconfigure.

    Deleting an instance used to manage a REMOTE firewall can disconnect it
    after apply. Identify the actual management path (ask if uncertain);
    coordinate REMOTE before LOCAL, with no interim REMOTE status polling.
    """
    return await _delete(get_api(ctx, site), "wireguard", "instance", uuid)


@mcp.tool()
async def opn_kea_list(
    ctx: Context, resource: KeaResourceName, site: SiteName = "", search: str = "", limit: int = 100
) -> dict[str, Any]:
    """List Kea configuration resources (static reservations, subnets, options, HA peers).

    The resource parameter is a SINGLE exact name, NOT 'reservations' or 'hosts':
    DHCPv4: reservation4, subnet4, option4, ha_peer4.
    DHCPv6: reservation6, subnet6, option6, pd_pool6, ha_peer6.

    For a static DHCPv4 MAC reservation, call
    opn_kea_list(resource="reservation4", search="docker", site="<site>").
    Find the UUID in the returned rows, then use opn_kea_get and opn_kea_patch
    with resource="reservation4" and that UUID. Use changes={"hw_address":
    "aa:bb:cc:dd:ee:ff"} to change the MAC address. After a successful
    patch, explicitly call opn_service_apply(service="kea", site="<site>").
    This lists configured reservations, not live DHCP leases (which have
    separate opn_list_kea_leases and opn_kea_list_leases6 tools).
    """
    return await _list(get_api(ctx, site), "kea", resource, search, limit)


@mcp.tool()
async def opn_kea_get(ctx: Context, resource: KeaResourceName, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Read one configured Kea object by UUID.

    For a DHCPv4 static reservation use resource="reservation4" and the UUID
    returned by opn_kea_list(resource="reservation4"). The result contains
    fields such as "hw_address" and "ip_address" (subject to the installed
    OPNsense model). Use reservation6 for DHCPv6 reservations.
    """
    return await _get(get_api(ctx, site), "kea", resource, uuid)


@mcp.tool()
async def opn_kea_add(
    ctx: Context, resource: KeaResourceName, fields: dict[str, str], site: SiteName = ""
) -> dict[str, Any]:
    """Stage creation of one Kea configuration object; does not apply.

    For a DHCPv4 static MAC/IP reservation use resource="reservation4".
    Fields must be valid for the target OPNsense version (e.g. "hw_address",
    "ip_address"); they are checked against that site's actual MVC form.
    Use opn_service_apply(service="kea", site="<site>") after success.
    """
    return await _add(get_api(ctx, site), "kea", resource, fields)


@mcp.tool()
async def opn_kea_patch(
    ctx: Context, resource: KeaResourceName, uuid: str, changes: dict[str, str], site: SiteName = ""
) -> dict[str, Any]:
    """Stage a targeted read-before-write patch of an existing Kea object.

    For a DHCPv4 MAC reservation: list resource="reservation4" to obtain the
    correct UUID and site, then call opn_kea_patch(resource="reservation4",
    uuid="<uuid>", changes={"hw_address": "aa:bb:cc:dd:ee:ff"},
    site="<site>"). Other fields/reservations are not modified.
    No automatic apply: afterwards call opn_service_apply(service="kea",
    site="<site>") separately. Do not confuse configured reservations
    with DHCP lease records.
    """
    return await _patch(get_api(ctx, site), "kea", resource, uuid, changes)


@mcp.tool()
async def opn_kea_delete(ctx: Context, resource: KeaResourceName, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Stage deletion of one explicitly identified Kea configuration object.

    To delete a DHCPv4 static reservation use resource="reservation4" and
    its UUID from opn_kea_list, not a live lease identifier. This does not
    apply changes; use opn_service_apply(service="kea", site="<site>").
    """
    return await _delete(get_api(ctx, site), "kea", resource, uuid)


@mcp.tool()
async def opn_radvd_list(ctx: Context, site: SiteName = "", search: str = "") -> dict[str, Any]:
    """List radvd IPv6 Router Advertisement entries."""
    return await _list(get_api(ctx, site), "radvd", "entry", search, 100)


@mcp.tool()
async def opn_radvd_get(ctx: Context, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Read one radvd entry."""
    return await _get(get_api(ctx, site), "radvd", "entry", uuid)


@mcp.tool()
async def opn_radvd_add(ctx: Context, fields: dict[str, str], site: SiteName = "") -> dict[str, Any]:
    """Create one radvd entry; does not reconfigure daemon."""
    return await _add(get_api(ctx, site), "radvd", "entry", fields)


@mcp.tool()
async def opn_radvd_patch(ctx: Context, uuid: str, changes: dict[str, str], site: SiteName = "") -> dict[str, Any]:
    """Read-before-write patch one radvd entry without affecting others."""
    return await _patch(get_api(ctx, site), "radvd", "entry", uuid, changes)


@mcp.tool()
async def opn_radvd_delete(ctx: Context, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Delete one radvd entry without restarting radvd."""
    return await _delete(get_api(ctx, site), "radvd", "entry", uuid)


@mcp.tool()
async def opn_radvd_toggle(ctx: Context, uuid: str, enabled: bool, site: SiteName = "") -> dict[str, Any]:
    """Enable/disable one radvd entry, no automatic reconfigure."""
    return await _toggle(get_api(ctx, site), "radvd", "entry", uuid, enabled)


@mcp.tool()
async def opn_unbound_list(
    ctx: Context, resource: UnboundResourceName, site: SiteName = "", search: str = "", limit: int = 100
) -> dict[str, Any]:
    """List Unbound host overrides, forwards, host aliases, ACLs or DNSBL objects.

    Valid resource values: host (host overrides), forward (forward zones), host_alias (aliases of overrides), acl (access controls), dnsbl (blocklist configurations). The 'search' parameter searches these configured objects; it is not an arbitrary API endpoint.
    """    return await _list(get_api(ctx, site), "unbound", resource, search, limit)


@mcp.tool()
async def opn_unbound_get(ctx: Context, resource: UnboundResourceName, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Read one Unbound configuration object with secrets removed.

    resource must be host, forward, host_alias, acl or dnsbl. Use the UUID from opn_unbound_list(resource=<same-value>). 'uuid' is a configuration object UUID, not an IP address.
    """    return await _get(get_api(ctx, site), "unbound", resource, uuid)


@mcp.tool()
async def opn_unbound_add(ctx: Context, resource: UnboundResourceName, fields: dict[str, str], site: SiteName = "") -> dict[str, Any]:
    """Create one Unbound MVC object without restarting DNS.

    resource must be host, forward, host_alias, acl or dnsbl. 'fields' is a JSON object mapping exact model field names to strings; fields are checked against this site's installed MVC model. Do not guess field names or infer them from other OPNsense versions. Apply later with opn_service_apply(service='unbound').
    """    return await _add(get_api(ctx, site), "unbound", resource, fields)


@mcp.tool()
async def opn_unbound_patch(
    ctx: Context, resource: UnboundResourceName, uuid: str, changes: dict[str, str], site: SiteName = ""
) -> dict[str, Any]:
    """Read-before-write patch an Unbound MVC object without modifying other records.

    resource must be host, forward, host_alias, acl or dnsbl. Obtain the UUID and current field names with opn_unbound_list and opn_unbound_get; 'changes' maps only fields to modify to string values. Apply later with opn_service_apply(service='unbound').
    """    return await _patch(get_api(ctx, site), "unbound", resource, uuid, changes)


@mcp.tool()
async def opn_unbound_delete(ctx: Context, resource: UnboundResourceName, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Delete one Unbound MVC object; explicit apply remains separate.

    resource must be host, forward, host_alias, acl or dnsbl. Obtain the UUID using opn_unbound_list; this stages deletion only. Apply later with opn_service_apply(service='unbound').
    """    return await _delete(get_api(ctx, site), "unbound", resource, uuid)


@mcp.tool()
async def opn_unbound_toggle(ctx: Context, resource: UnboundResourceName, uuid: str, enabled: bool, site: SiteName = "") -> dict[str, Any]:
    """Enable or disable one Unbound MVC object; no DNS reconfigure.

    resource must be host, forward, host_alias, acl or dnsbl. 'enabled' is a Boolean target state (true/false), not a toggle command; apply later with opn_service_apply(service='unbound').
    """    return await _toggle(get_api(ctx, site), "unbound", resource, uuid, enabled)


@mcp.tool()
async def opn_service_apply(ctx: Context, service: ApplyServiceName, site: SiteName = "") -> dict[str, Any]:
    """Explicitly apply pending WireGuard/Kea/radvd/Unbound changes on one site.

    service is exactly one of: wireguard, kea, radvd, unbound.

    May restart services or disrupt traffic. This is not called automatically
    by the CRUD helpers. Cross-site sequencing is the model's responsibility.

    CRITICAL for service="wireguard": If a REMOTE OPNsense is managed through
    the WireGuard tunnel being changed, applying its side may immediately
    sever the management connection. For coordinated changes to both ends,
    first change and apply REMOTE, then change and apply the independently
    reachable LOCAL side. Do NOT poll/check REMOTE after its apply while the
    tunnel is down: connectivity may return only once LOCAL has also been
    updated and applied. Verify REMOTE only after the tunnel is restored.
    Do not infer LOCAL/REMOTE from site names: establish the actual management
    access path. If uncertain whether access uses the affected VPN, or which
    side is LOCAL versus REMOTE, ask the user BEFORE changing/applying.
    This tool does not orchestrate the other site or guarantee reconnection.
    """
    if service not in {"wireguard", "kea", "radvd", "unbound"}:
        raise ValueError("Unsupported service; choose wireguard, kea, radvd or unbound")
    api = get_api(ctx, site)
    api.require_writes()
    result = await api.post(f"mvc.service.{service}.reconfigure")
    get_config_cache(ctx, site).invalidate()
    return {"service": service, "result": _sanitize(result)}


@mcp.tool()
async def opn_kea_list_leases6(ctx: Context, search: str = "", limit: int = 100, site: SiteName = "") -> dict[str, Any]:
    """List Kea DHCPv6 leases without modifying lease state."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be 1..500")
    result = await get_api(ctx, site).post(
        "mvc.kea.leases6.search",
        {"current": 1, "rowCount": limit, "searchPhrase": search},
    )
    return cast(dict[str, Any], _sanitize(result))


@mcp.tool()
async def opn_kea_delete_lease(ctx: Context, ip: str, site: SiteName = "") -> dict[str, Any]:
    """Explicitly remove a Kea lease by IP address. This does not change reservations."""
    import ipaddress

    address = str(ipaddress.ip_address(ip))
    api = get_api(ctx, site)
    api.require_writes()
    return cast(dict[str, Any], _sanitize(await api.post("mvc.kea.leases.del", path_suffix=address)))


@mcp.tool()
async def opn_mvc_get_settings(ctx: Context, subsystem: SettingsSubsystemName, site: SiteName = "") -> dict[str, Any]:
    """Read global settings of Kea DHCPv4/v6/DDNS/control-agent, radvd, Unbound or WireGuard.

    subsystem must be exactly one of: kea_dhcpv4, kea_dhcpv6,
    kea_ctrl_agent, kea_ddns, radvd, unbound, wireguard.
    Read this before patching settings to discover available field names.
    """
    if subsystem not in GLOBAL_SETTINGS:
        raise ValueError("Unsupported settings subsystem")
    _, root = GLOBAL_SETTINGS[subsystem]
    result = await get_api(ctx, site).get(f"mvc.settings.{subsystem}.get")
    return {"subsystem": subsystem, "settings": _sanitize(result.get(root, {}))}


@mcp.tool()
async def opn_mvc_patch_settings(
    ctx: Context, subsystem: SettingsSubsystemName, changes: dict[str, Any], site: SiteName = ""
) -> dict[str, Any]:
    """Patch selected global settings of one subsystem, never apply automatically.

    subsystem must be exactly one of: kea_dhcpv4, kea_dhcpv6,
    kea_ctrl_agent, kea_ddns, radvd, unbound, wireguard.
    changes is a JSON object using only existing top-level keys returned by
    opn_mvc_get_settings for the same subsystem on the same site.

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
