"""Individually callable firmware update controls; no orchestration workflow."""

from __future__ import annotations

from asyncio import TimeoutError, sleep, wait_for
from typing import Any

import httpx
from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPIError

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


def _is_temporary_outage(exc: Exception) -> bool:
    """Only transport timeouts/outages and transient gateway errors are retryable."""
    if isinstance(exc, (TimeoutError, httpx.TransportError)):
        return True
    if isinstance(exc, OPNsenseAPIError):
        return exc.status_code in (502, 503, 504) or (
            exc.status_code == 0
            and str(exc).startswith(
                ("Connection failed:", "Request timed out:", "Failed to connect to OPNsense")
            )
        )
    return False


@mcp.tool()
async def opn_monitor_firmware_update(
    ctx: Context,
    site: str = "",
    previous_version: str = "",
    max_checks: int = 3,
    poll_interval_seconds: int = 2,
) -> dict[str, Any]:
    """Briefly monitor an existing firmware update, tolerating network outages.

    Read-only: DOES NOT trigger an update, reboot, or other write. Performs
    at most 3 API checks (5 seconds maximum per check); repeat tool calls for
    longer-running updates. Transient connection errors during a reboot are
    treated as 'temporarily_unreachable', NOT as update failure.

    Returns states 'running', 'temporarily_unreachable', 'reboot_required',
    'backend_done', or 'indeterminate'. 'backend_done' means the OPNsense
    firmware backend emitted ***DONE***; it does not prove that a particular
    job succeeded or that packages changed. Supply previous_version to get a
    comparison with the currently installed version when accessible.
    """
    if not 1 <= max_checks <= 3:
        raise ValueError("max_checks must be between 1 and 3")
    if not 1 <= poll_interval_seconds <= 3:
        raise ValueError("poll_interval_seconds must be between 1 and 3")
    if len(previous_version) > 64:
        raise ValueError("previous_version is too long")

    api = get_api(ctx, site)
    seen_backend: str | None = None
    outages = 0
    last_log = ""

    for check in range(1, max_checks + 1):
        try:
            progress = await wait_for(api.get("firmware.upgradestatus"), timeout=5.0)
        except (OPNsenseAPIError, httpx.TransportError, TimeoutError) as exc:
            if not _is_temporary_outage(exc):
                raise
            outages += 1
            if check == max_checks:
                return {
                    "state": "temporarily_unreachable",
                    "checks": check,
                    "outages": outages,
                    "last_backend_status": seen_backend,
                    "next_step": "Retry this monitor; do not reissue the firmware update",
                }
        else:
            raw_status = progress.get("status")
            status = raw_status if isinstance(raw_status, str) else ""
            raw_log = progress.get("log")
            last_log = raw_log[-1200:] if isinstance(raw_log, str) else ""
            seen_backend = status or "unknown"

            if status == "done":
                result: dict[str, Any] = {
                    "state": "backend_done",
                    "checks": check,
                    "outages": outages,
                    "last_backend_status": status,
                    "log_tail": last_log,
                    "note": "Backend finished; its status is not correlated to a specific job ID",
                }
                try:
                    firmware = await wait_for(api.get("firmware.status"), timeout=5.0)
                except (OPNsenseAPIError, httpx.TransportError, TimeoutError) as exc:
                    if not _is_temporary_outage(exc):
                        raise
                    result["verification"] = "temporarily_unreachable"
                    result["next_step"] = "Retry monitor and verify firmware version"
                    return result
                product = firmware.get("product")
                if isinstance(product, dict):
                    version = product.get("product_version")
                else:
                    version = firmware.get("product_version")
                if isinstance(version, str):
                    result["current_version"] = version
                    if previous_version:
                        result["previous_version"] = previous_version
                        result["version_changed"] = version != previous_version
                result["firmware_status"] = firmware.get("status")
                result["next_step"] = "Check available updates; do not infer success from backend completion alone"
                return result
            if status == "reboot":
                return {
                    "state": "reboot_required",
                    "checks": check,
                    "outages": outages,
                    "log_tail": last_log,
                    "next_step": "Manual decision required; the monitor will not reboot",
                }
            if status == "error":
                return {
                    "state": "indeterminate",
                    "checks": check,
                    "outages": outages,
                    "log_tail": last_log,
                    "note": "Empty/missing backend log is not proof of update failure",
                }
            if status != "running":
                return {
                    "state": "indeterminate",
                    "checks": check,
                    "outages": outages,
                    "last_backend_status": seen_backend,
                    "log_tail": last_log,
                }
        if check < max_checks:
            await sleep(poll_interval_seconds)

    return {
        "state": "temporarily_unreachable" if outages == max_checks else "running",
        "checks": max_checks,
        "outages": outages,
        "last_backend_status": seen_backend,
        "log_tail": last_log,
        "next_step": "Call this monitor again; never restart the update merely because it is still running",
    }


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
