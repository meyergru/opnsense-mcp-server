"""Individually callable firmware update controls; no orchestration workflow."""

from __future__ import annotations

from asyncio import sleep, wait_for
from typing import Any

import httpx
from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.server import get_api, mcp
from opnsense_mcp.tool_types import BoundedFirmwareChecks, BoundedFirmwarePollInterval, SiteName


def _backend_is_idle(status: dict[str, Any]) -> bool:
    """Only accept known free-lock statuses (OPNsense 26.7: ready; older: 0)."""
    return status.get("status") in ("ready", 0, "0", False)


@mcp.tool()
async def opn_firmware_update_running(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Read whether the OPNsense firmware backend reports a running update.

    In OPNsense 26.7, status="ready" means the firmware lock is free;
    status="busy" means the lock is held. Do not infer activity from the
    tool name; return the actual backend state.

    Args:
        site: Exact configured OPNsense site alias from opn_list_targets. Empty is allowed only if one site is
            configured. Optional (default: "").
    """
    return await get_api(ctx, site).get("firmware.running")


@mcp.tool()
async def opn_firmware_update_progress(ctx: Context, site: SiteName = "") -> dict[str, Any]:
    """Read asynchronous firmware update status and log without modifying state.

    Status is usually 'running', 'done', 'reboot' or 'error'. An accepted
    update job is not proof of completion. Do not trigger further updates
    while the previous job is running or when status requires reboot.

    Args:
        site: Exact configured OPNsense site alias from opn_list_targets. Empty is allowed only if one site is
            configured. Optional (default: "").
    """
    return await get_api(ctx, site).get("firmware.upgradestatus")


def _is_temporary_outage(exc: Exception) -> bool:
    """Only transport timeouts/outages and transient gateway errors are retryable."""
    if isinstance(exc, (TimeoutError, httpx.TransportError)):
        return True
    if isinstance(exc, OPNsenseAPIError):
        return exc.status_code in (502, 503, 504) or (
            exc.status_code == 0
            and str(exc).startswith(("Connection failed:", "Request timed out:", "Failed to connect to OPNsense"))
        )
    return False


@mcp.tool()
async def opn_monitor_firmware_update(
    ctx: Context,
    site: SiteName = "",
    previous_version: str = "",
    max_checks: BoundedFirmwareChecks = 3,
    poll_interval_seconds: BoundedFirmwarePollInterval = 2,
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

    Args:
        site: Exact configured OPNsense site alias from opn_list_targets. Empty is allowed only if one site is
            configured. Optional (default: "").
        previous_version: Previously installed firmware version used for comparison; empty means no version
            comparison. Optional (default: "").
        max_checks: Number of checks in this call; must be 1..3. Optional (default: 3).
        poll_interval_seconds: Seconds between checks; must be 1..3. Optional (default: 2).
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
async def opn_start_firmware_update(ctx: Context, confirm: bool = False, site: SiteName = "") -> dict[str, Any]:
    """Start a regular OPNsense firmware update, including one requiring reboot.

    Requires explicit confirm=true and normal write OR maintenance permission.
    Checks firmware.running status="ready" (OPNsense 26.7 free lock; "busy"
    rejects) and refreshes the repository status before submission.
    Only status='update' starts a regular installation.
    If 'upgrade' is reported, use opn_start_firmware_upgrade instead.
    A ZFS snapshot should be created and verified by the caller beforehand.

    This starts an asynchronous backend job, not a completed update. It may
    itself reboot the firewall; temporary API outages are expected. Never
    resubmit a job merely because the connection dropped. Monitor progress
    and verify the installed version and remaining updates independently.

    Args:
        confirm: Explicit confirmation before this operation; false blocks mutation. Optional (default: False).
        site: Exact configured OPNsense site alias from opn_list_targets. Empty is allowed only if one site is
            configured. Optional (default: "").
    """
    api = get_api(ctx, site)
    api.require_write_operation("firmware.update")
    if not confirm:
        return {"error": "Explicit confirm=true required to start a firmware update"}
    running = await api.get("firmware.running")
    if not _backend_is_idle(running):
        return {"error": "Firmware backend is not confirmed idle; update refused", "running": running.get("status")}
    fresh_status = await api.post("firmware.status")
    if fresh_status.get("status") != "update":
        return {
            "error": "Regular update refused: fresh firmware status is not 'update'",
            "firmware_status": fresh_status.get("status"),
        }
    result = await api.post("firmware.update")
    return {"job": result, "note": "Update submitted; monitor progress, reboot and installed version"}


@mcp.tool()
async def opn_start_firmware_upgrade(ctx: Context, confirm: bool = False, site: SiteName = "") -> dict[str, Any]:
    """Start a major-release OPNsense firmware upgrade asynchronously.

    Requires explicit confirm=true and normal write OR maintenance permission.
    Only permitted when a fresh opn_check_firmware_updates reports
    status='upgrade' and firmware.running returns status="ready" (idle
    backend lock on OPNsense 26.7). Busy or unknown states are refused. The installer may reboot itself,
    and the firewall API can be unreachable for an extended period.
    Create and verify a snapshot first. Do not retry on timeout.

    Args:
        confirm: Explicit confirmation before this operation; false blocks mutation. Optional (default: False).
        site: Exact configured OPNsense site alias from opn_list_targets. Empty is allowed only if one site is
            configured. Optional (default: "").
    """
    api = get_api(ctx, site)
    api.require_write_operation("firmware.upgrade")
    if not confirm:
        return {"error": "Explicit confirm=true required to start a major firmware upgrade"}
    running = await api.get("firmware.running")
    if not _backend_is_idle(running):
        return {"error": "Firmware backend is not confirmed idle; upgrade refused", "running": running.get("status")}
    fresh_status = await api.post("firmware.status")
    if fresh_status.get("status") != "upgrade":
        return {
            "error": "Major upgrade refused: fresh firmware status is not 'upgrade'",
            "firmware_status": fresh_status.get("status"),
        }
    result = await api.post("firmware.upgrade")
    return {"job": result, "note": "Major upgrade submitted; monitor progress, reboot and installed version"}


@mcp.tool()
async def opn_reboot(ctx: Context, confirm: bool = False, site: SiteName = "") -> dict[str, Any]:
    """Explicitly reboot a firewall only after firmware reports a reboot marker.

    Requires confirm=true, maintenance/write permission, a confirmed idle
    backend and 'reboot' from the firmware progress endpoint. The global log
    cannot be correlated with a job UUID, so callers must independently verify
    that this reboot pertains to the intended maintenance operation.

    Args:
        confirm: Explicit confirmation before this operation; false blocks mutation. Optional (default: False).
        site: Exact configured OPNsense site alias from opn_list_targets. Empty is allowed only if one site is
            configured. Optional (default: "").
    """
    api = get_api(ctx, site)
    api.require_write_operation("firmware.reboot")
    if not confirm:
        return {"error": "Explicit confirm=true required to reboot OPNsense"}
    running = await api.get("firmware.running")
    if not _backend_is_idle(running):
        return {"error": "Firmware backend is not confirmed idle; reboot refused", "running": running.get("status")}
    progress = await api.get("firmware.upgradestatus")
    if progress.get("status") != "reboot":
        return {
            "error": "Explicit reboot refused: firmware backend has no reboot marker",
            "progress_status": progress.get("status"),
        }
    result = await api.post("firmware.reboot")
    return {"job": result, "note": "Reboot submitted; API loss does not prove failure"}
