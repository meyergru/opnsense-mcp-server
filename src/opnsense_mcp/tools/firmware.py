"""Individually callable firmware update controls; no orchestration workflow."""

from __future__ import annotations

from typing import Any

from fastmcp import Context

from opnsense_mcp.server import get_api, mcp


def _no_reboot_update_available(status: dict[str, Any]) -> bool:
    """Deny update when reboot information is missing or not unequivocally no."""
    return (
        status.get("status") == "update"
        and status.get("status_reboot") in (0, "0", False)
        and status.get("needs_reboot") in (0, "0", False)
        and "status_reboot" in status
        and "needs_reboot" in status
    )


@mcp.tool()
async def opn_firmware_update_running(ctx: Context, site: str = "") -> dict[str, Any]:
    """Read whether the OPNsense firmware backend reports a running update."""
    return await get_api(ctx, site).get("firmware.running")


@mcp.tool()
async def opn_firmware_update_progress(ctx: Context, site: str = "") -> dict[str, Any]:
    """Read asynchronous firmware update status and log without modifying state.

    Status is usually 'running', 'done', 'reboot' or 'error'. An accepted
    update job is not proof of completion. Do not trigger further updates
    while the previous job is running or when status requires reboot.
    """
    return await get_api(ctx, site).get("firmware.upgradestatus")


@mcp.tool()
async def opn_start_firmware_update(
    ctx: Context, confirm: bool = False, site: str = ""
) -> dict[str, Any]:
    """Start an OPNsense minor/package firmware update asynchronously.

    Requires this site's write permission and confirm=true. Immediately
    refreshes firmware status, and proceeds only if updates are available
    with *explicit* no-reboot indicators. Does not create a snapshot,
    install plugins individually, trigger an explicit reboot or run a major
    version upgrade. Create/verify a ZFS snapshot first if desired.

    Note: OPNsense firmware backend owns the upgrade process; the MCP
    server CANNOT guarantee that services stay up or a reboot never occurs.
    The result 'status=ok' with msg_uuid only means the job was STARTED.
    Poll opn_firmware_update_progress, then recheck firmware status.
    """
    api = get_api(ctx, site)
    api.require_writes()
    if not confirm:
        return {"error": "Explicit confirm=true required to start a firmware update"}
    fresh_status = await api.post("firmware.status")
    if not _no_reboot_update_available(fresh_status):
        return {
            "error": "Update refused: not an available minor update with explicitly no reboot needed",
            "firmware_status": fresh_status.get("status"),
            "status_reboot": fresh_status.get("status_reboot"),
            "needs_reboot": fresh_status.get("needs_reboot"),
        }
    result = await api.post("firmware.update")
    return {"job": result, "note": "Update started; poll opn_firmware_update_progress for completion"}
