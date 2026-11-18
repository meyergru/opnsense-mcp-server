"""Firmware update primitives and bounded, reboot-tolerant monitoring tests."""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import AsyncMock, patch

import pytest

from opnsense_mcp.api_client import OPNsenseAPIError, WriteDisabledError
from opnsense_mcp.tools.firmware import (
    _backend_is_idle,
    opn_firmware_update_progress,
    opn_firmware_update_running,
    opn_monitor_firmware_update,
    opn_reboot,
    opn_start_firmware_update,
    opn_start_firmware_upgrade,
)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("ready", True),
        ("busy", False),
        ("0", True),
        (0, True),
        (False, True),
        ("1", False),
        (1, False),
        (True, False),
        ("idle", False),
        ("error", False),
        (None, False),
        ("", False),
    ],
)
def test_firmware_backend_idle_status_semantics(status, expected):
    assert _backend_is_idle({"status": status}) is expected


async def test_running_status_read_only(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"status": "0"})
    result = await opn_firmware_update_running(mock_ctx)
    assert result == {"status": "0"}
    mock_api.get.assert_awaited_once_with("firmware.running")


async def test_raw_progress_read_only(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"status": "running", "log": "downloading"})
    result = await opn_firmware_update_progress(mock_ctx)
    assert result["status"] == "running"
    mock_api.get.assert_awaited_once_with("firmware.upgradestatus")


@pytest.fixture
def maintenance(mock_api, mock_ctx):
    """Read-only API with only firmware-maintenance writes enabled."""
    mock_api._config = replace(mock_api._config, maintenance_enabled=True)
    return mock_api, mock_ctx


async def test_update_start_requires_permission(mock_api, mock_ctx):
    mock_api.get = AsyncMock()
    mock_api.post = AsyncMock()
    with pytest.raises(WriteDisabledError):
        await opn_start_firmware_update(mock_ctx, confirm=True)
    mock_api.get.assert_not_awaited()
    mock_api.post.assert_not_awaited()


async def test_update_start_requires_confirmation(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock()
    mock_api_writes.post = AsyncMock()
    result = await opn_start_firmware_update(mock_ctx_writes)
    assert "error" in result
    mock_api_writes.get.assert_not_awaited()
    mock_api_writes.post.assert_not_awaited()


@pytest.mark.parametrize("status", ["none", "upgrade", "error", None])
async def test_update_denies_non_update_status(maintenance, status):
    api, ctx = maintenance
    api.get = AsyncMock(return_value={"status": "0"})
    api.post = AsyncMock(return_value={"status": status})
    result = await opn_start_firmware_update(ctx, confirm=True)
    assert "error" in result
    api.post.assert_awaited_once_with("firmware.status")


@pytest.mark.parametrize("running", ["1", "yes", "busy", "idle", None])
async def test_update_denies_non_idle_backend(maintenance, running):
    api, ctx = maintenance
    api.get = AsyncMock(return_value={"status": running})
    api.post = AsyncMock()
    result = await opn_start_firmware_update(ctx, confirm=True)
    assert "error" in result
    api.post.assert_not_awaited()


async def test_update_accepts_opnsense_ready_lock(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(return_value={"status": "ready"})
    api.post = AsyncMock(side_effect=[{"status": "update"}, {"status": "ok", "msg_uuid": "job-ready"}])
    result = await opn_start_firmware_update(ctx, confirm=True)
    assert result["job"]["msg_uuid"] == "job-ready"
    assert [call.args[0] for call in api.post.await_args_list] == ["firmware.status", "firmware.update"]


async def test_update_allows_reboot_required_on_maintenance_site(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(return_value={"status": "0"})
    api.post = AsyncMock(
        side_effect=[
            {"status": "update", "status_reboot": "1", "needs_reboot": 1},
            {"status": "ok", "msg_uuid": "job-123"},
        ]
    )
    result = await opn_start_firmware_update(ctx, confirm=True)
    assert result["job"]["msg_uuid"] == "job-123"
    assert [call.args[0] for call in api.post.await_args_list] == ["firmware.status", "firmware.update"]


async def test_major_upgrade_requires_upgrade_status(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(return_value={"status": "0"})
    api.post = AsyncMock(return_value={"status": "update"})
    result = await opn_start_firmware_upgrade(ctx, confirm=True)
    assert "error" in result
    api.post.assert_awaited_once_with("firmware.status")


async def test_major_upgrade_starts_only_on_explicit_status(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(return_value={"status": "0"})
    api.post = AsyncMock(
        side_effect=[{"status": "upgrade", "status_reboot": "1"}, {"status": "ok", "msg_uuid": "major-123"}]
    )
    result = await opn_start_firmware_upgrade(ctx, confirm=True)
    assert result["job"]["msg_uuid"] == "major-123"
    assert [call.args[0] for call in api.post.await_args_list] == ["firmware.status", "firmware.upgrade"]


async def test_major_upgrade_accepts_opnsense_ready_lock(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(return_value={"status": "ready"})
    api.post = AsyncMock(side_effect=[{"status": "upgrade"}, {"status": "ok", "msg_uuid": "major-ready"}])
    result = await opn_start_firmware_upgrade(ctx, confirm=True)
    assert result["job"]["msg_uuid"] == "major-ready"
    assert [call.args[0] for call in api.post.await_args_list] == ["firmware.status", "firmware.upgrade"]


async def test_major_upgrade_requires_confirmation(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock()
    api.post = AsyncMock()
    assert "error" in await opn_start_firmware_upgrade(ctx)
    api.get.assert_not_awaited()
    api.post.assert_not_awaited()


async def test_reboot_requires_backend_reboot_marker(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(side_effect=[{"status": "0"}, {"status": "done"}])
    api.post = AsyncMock()
    assert "error" in await opn_reboot(ctx, confirm=True)
    api.post.assert_not_awaited()


async def test_reboot_requires_confirmation(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock()
    api.post = AsyncMock()
    assert "error" in await opn_reboot(ctx)
    api.get.assert_not_awaited()
    api.post.assert_not_awaited()


async def test_reboot_submits_only_with_marker_and_idle_backend(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(side_effect=[{"status": "0"}, {"status": "reboot", "log": "***REBOOT***"}])
    api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "reboot-123"})
    result = await opn_reboot(ctx, confirm=True)
    assert result["job"]["msg_uuid"] == "reboot-123"
    api.post.assert_awaited_once_with("firmware.reboot")


async def test_reboot_accepts_opnsense_ready_lock_with_reboot_marker(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(side_effect=[{"status": "ready"}, {"status": "reboot"}])
    api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "reboot-ready"})
    result = await opn_reboot(ctx, confirm=True)
    assert result["job"]["msg_uuid"] == "reboot-ready"
    api.post.assert_awaited_once_with("firmware.reboot")


async def test_reboot_denies_active_backend(maintenance):
    api, ctx = maintenance
    api.get = AsyncMock(return_value={"status": "1"})
    api.post = AsyncMock()
    assert "error" in await opn_reboot(ctx, confirm=True)
    api.post.assert_not_awaited()


async def test_monitor_running_is_bounded_and_never_writes(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"status": "running", "log": "installing"})
    mock_api.post = AsyncMock()
    with patch("opnsense_mcp.tools.firmware.sleep", new_callable=AsyncMock) as wait:
        result = await opn_monitor_firmware_update(mock_ctx, max_checks=3)
    assert result["state"] == "running"
    assert result["checks"] == 3
    assert mock_api.get.await_count == 3
    assert wait.await_count == 2
    mock_api.post.assert_not_awaited()


async def test_monitor_recovers_after_transient_connection_error(mock_api, mock_ctx):
    mock_api.get = AsyncMock(
        side_effect=[
            OPNsenseAPIError("Connection failed: core/firmware/upgradestatus"),
            {"status": "running", "log": "updating"},
        ]
    )
    with patch("opnsense_mcp.tools.firmware.sleep", new_callable=AsyncMock):
        result = await opn_monitor_firmware_update(mock_ctx, max_checks=2)
    assert result["state"] == "running"
    assert result["outages"] == 1


async def test_monitor_continuous_reboot_outage_is_not_failed(mock_api, mock_ctx):
    mock_api.get = AsyncMock(side_effect=OPNsenseAPIError("Request timed out: firmware"))
    with patch("opnsense_mcp.tools.firmware.sleep", new_callable=AsyncMock):
        result = await opn_monitor_firmware_update(mock_ctx, max_checks=3)
    assert result["state"] == "temporarily_unreachable"
    assert result["outages"] == 3
    assert "do not reissue" in result["next_step"]


async def test_monitor_reports_reboot_without_triggering_one(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"status": "reboot", "log": "***REBOOT***"})
    mock_api.post = AsyncMock()
    result = await opn_monitor_firmware_update(mock_ctx)
    assert result["state"] == "reboot_required"
    assert mock_api.get.await_count == 1
    mock_api.post.assert_not_awaited()


async def test_monitor_backend_done_verifies_version_but_not_job_identity(mock_api, mock_ctx):
    mock_api.get = AsyncMock(
        side_effect=[
            {"status": "done", "log": "xyz***DONE***"},
            {"status": "none", "product": {"product_version": "26.7.8_3"}},
        ]
    )
    result = await opn_monitor_firmware_update(mock_ctx, previous_version="26.7.8_2")
    assert result["state"] == "backend_done"
    assert result["version_changed"] is True
    assert result["current_version"] == "26.7.8_3"
    assert "not correlated" in result["note"]


async def test_monitor_done_but_verification_unreachable(mock_api, mock_ctx):
    mock_api.get = AsyncMock(
        side_effect=[
            {"status": "done", "log": "***DONE***"},
            OPNsenseAPIError("Connection failed: firmware.status"),
        ]
    )
    result = await opn_monitor_firmware_update(mock_ctx)
    assert result["state"] == "backend_done"
    assert result["verification"] == "temporarily_unreachable"


async def test_monitor_does_not_hide_unauthorized_access(mock_api, mock_ctx):
    mock_api.get = AsyncMock(side_effect=OPNsenseAPIError("Forbidden", status_code=403))
    with pytest.raises(OPNsenseAPIError, match="Forbidden"):
        await opn_monitor_firmware_update(mock_ctx)


async def test_monitor_empty_log_is_indeterminate_not_failed(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"status": "error", "log": ""})
    result = await opn_monitor_firmware_update(mock_ctx)
    assert result["state"] == "indeterminate"


@pytest.mark.parametrize("max_checks,interval", [(0, 2), (4, 2), (2, 0), (2, 4)])
async def test_monitor_rejects_unbounded_polling(mock_ctx, max_checks, interval):
    with pytest.raises(ValueError):
        await opn_monitor_firmware_update(mock_ctx, max_checks=max_checks, poll_interval_seconds=interval)
