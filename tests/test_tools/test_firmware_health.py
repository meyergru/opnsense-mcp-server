"""Native OPNsense firmware integrity/dependency health-audit tests (offline)."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import OperationEffect, operation_effect
from opnsense_mcp.tools.firmware_cve import (
    _HEALTH_MARKER, _DONE_MARKER, _parse_health_log,
    opn_firmware_health_audit, opn_firmware_health_audit_result,
    opn_firmware_cve_audit_result,
)

_CLEAN_HEALTH = (
    _HEALTH_MARKER
    + "\n>>> Check installed kernel version\nVersion 26.7 is correct.\n"
    + ">>> Check for missing or altered kernel files\nNo problems detected.\n"
    + ">>> Check installed base version\nVersion 26.7 is correct.\n"
    + ">>> Check for missing or altered package files\nChecking all packages: .... done\n"
    + _DONE_MARKER
)
_ISSUE_HEALTH = _CLEAN_HEALTH.replace(
    "Checking all packages: .... done",
    "my-pkg-1: checksum mismatch for /usr/local/etc/affected.conf\n"
    "Package not installed: dependency-pkg",
)


def test_native_health_parser_is_conservative():
    ok = _parse_health_log(_CLEAN_HEALTH)
    assert ok["assessment"] == "no_anomalies_detected_in_report"
    assert ok["findings"] == []
    bad = _parse_health_log(_ISSUE_HEALTH)
    assert bad["assessment"] == "integrity_findings_reported"
    assert len(bad["findings"]) == 2
    assert "checksum mismatch" in bad["findings"][0]
    assert _parse_health_log(_HEALTH_MARKER + "\n" + _DONE_MARKER)["assessment"] == "inconclusive"
    assert _parse_health_log(_CLEAN_HEALTH.replace(_DONE_MARKER, ""))["assessment"] == "inconclusive"


async def test_health_allowed_on_read_only_and_requires_new_log(mock_api, mock_ctx):
    assert operation_effect("POST", "firmware.health") is OperationEffect.DIAGNOSTIC
    previous = {"status": "done", "log": _CLEAN_HEALTH}
    mock_api.get = AsyncMock(side_effect=[
        {"status": "idle"},
        previous,
        {"status": "done", "log": previous["log"]},
        {"status": "done", "log": _ISSUE_HEALTH},
    ])
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "health-job"})
    first = await opn_firmware_health_audit(mock_ctx, max_checks=1)
    assert first["state"] == "running"
    assert "assessment" not in first
    result = await opn_firmware_health_audit_result(mock_ctx, "health-job", max_checks=1)
    assert result["state"] == "complete"
    assert result["assessment"] == "integrity_findings_reported"
    assert result["findings"]
    mock_api.post.assert_awaited_once_with("firmware.health")
    wrong = await opn_firmware_cve_audit_result(mock_ctx, "health-job", max_checks=1)
    assert wrong["state"] == "no_matching_session"


async def test_stale_health_log_cannot_be_reported_clean(mock_api, mock_ctx):
    mock_api.get = AsyncMock(side_effect=lambda endpoint: (
        {"status": "idle"} if endpoint == "firmware.running" else
        {"status": "done", "log": _CLEAN_HEALTH}
    ))
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "stale-health"})
    result = await opn_firmware_health_audit(mock_ctx, max_checks=1)
    assert result["state"] == "running"
    assert "assessment" not in result
    follow = await opn_firmware_health_audit_result(mock_ctx, "stale-health", max_checks=1)
    assert follow["state"] == "running"


async def test_busy_backend_or_bad_limits_never_trigger_health(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"status": "busy"})
    mock_api.post = AsyncMock()
    assert (await opn_firmware_health_audit(mock_ctx))["state"] == "backend_busy"
    with pytest.raises(ValueError):
        await opn_firmware_health_audit(mock_ctx, max_checks=99)
    mock_api.post.assert_not_awaited()
