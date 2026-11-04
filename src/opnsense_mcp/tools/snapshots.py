"""Primitive OPNsense ZFS boot-environment snapshot tools.

Each tool represents one operation. Orchestration and recovery decisions are
left to the MCP caller. No snapshot is automatically activated or deleted.
"""

from __future__ import annotations

import re
from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, mcp
from opnsense_mcp.tool_types import SiteName

_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")


@mcp.tool()
async def opn_snapshot_supported(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Check whether ZFS boot-environment snapshots are supported on this site.

    Returns OPNsense's 'supported' flag. UFS installations do not support
    snapshots and must not be assumed to have this recovery mechanism.
    """
    return await get_api(ctx, site).get("snapshots.is_supported")


@mcp.tool()
async def opn_list_snapshots(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """List ZFS snapshots/boot environments and their active/boot states.

    Does not create, activate or delete a snapshot. Inspect the entries to
    verify that a snapshot was created before proceeding with changes.
    """
    return await get_api(ctx, site).get("snapshots.search")


@mcp.tool()
async def opn_get_snapshot(ctx: Context, uuid: str, site: SiteName = "") -> dict[str, Any]:
    """Inspect one ZFS snapshot by its UUID without changing it."""
    if not re.fullmatch(r"[a-fA-F0-9-]{8,64}", uuid):
        return {"error": "Invalid snapshot UUID"}
    return await get_api(ctx, site).get("snapshots.get", path_suffix=uuid)


@mcp.tool()
async def opn_create_snapshot(ctx: Context, name: str, site: SiteName = "", note: str = "") -> dict[str, Any]:
    """Create a new ZFS boot-environment snapshot with the requested name.

    Requires write access on this site. Uses POST /api/core/snapshots/add with
    name and optional note, without an existing UUID (new snapshot, not clone).
    This does NOT activate the snapshot or cause any reboot. Caller should use
    opn_list_snapshots to verify successful creation.
    """
    if not _NAME_PATTERN.fullmatch(name) or name in {".", ".."}:
        return {"error": "Invalid snapshot name (letters, digits, underscore, dot and hyphen only)"}
    if len(note) > 1024:
        return {"error": "Snapshot note is too long (max 1024 characters)"}
    api = get_api(ctx, site)
    api.require_writes()
    support = await api.get("snapshots.is_supported")
    if support.get("supported") is not True:
        return {"error": "ZFS snapshots are not confirmed supported on this site", "details": support}
    return await api.post("snapshots.add", {"name": name, "note": note})
