"""Native OPNsense VuXML firmware security-audit tests; no live device calls."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from opnsense_mcp.api_client import OperationEffect, operation_effect
from opnsense_mcp.tools.firmware_cve import (
    _AUDIT_MARKER,
    _DONE_MARKER,
    _parse_audit_log,
    opn_firmware_cve_audit,
    opn_firmware_cve_audit_result,
)

_AUDIT = (
    _AUDIT_MARKER
    + "\n"
    + "Currently running OPNsense 26.7.8_2 (amd64/OpenSSL)\n"
    + "python313-3.13.15 is vulnerable:\n"
    + "  Python -- poplib newline injection\n"
    + "  CVE: CVE-2025-15367\n"
    + "  WWW: https://vuxml.freebsd.org/freebsd/example.html\n"
    + "1 problem(s) in 1 installed package(s) found.\n"
    + _DONE_MARKER
)
_CLEAN = _AUDIT_MARKER + "\n0 problem(s) in 0 installed package(s) found.\n" + _DONE_MARKER


def test_parse_package_cves():
    result = _parse_audit_log(_AUDIT)
    assert result["assessment"] == "vulnerabilities_found"
    assert result["affected_package_count"] == 1
    assert result["packages"][0]["package"] == "python313-3.13.15"
    assert result["cves"] == ["CVE-2025-15367"]
    assert result["packages"][0]["references"][0].startswith("https://")


def test_clean_requires_explicit_zero_problems():
    assert _parse_audit_log(_CLEAN)["assessment"] == "clean"
    assert _parse_audit_log(_AUDIT_MARKER + "\n" + _DONE_MARKER)["assessment"] == "inconclusive"
    assert _parse_audit_log(_CLEAN + "\nError: could not fetch VuXML")["assessment"] == "inconclusive"


async def test_scan_is_allowed_in_read_only_mode(mock_api, mock_ctx):
    assert operation_effect("POST", "firmware.audit") is OperationEffect.DIAGNOSTIC
    calls: list[str] = []
    old = {"status": "done", "log": "***GOT REQUEST TO AUDIT SECURITY***\nold\n***DONE***"}

    async def fake_get(endpoint):
        calls.append(endpoint)
        if endpoint == "firmware.running":
            return {"status": "idle"}
        if endpoint == "firmware.upgradestatus":
            if calls.count("firmware.upgradestatus") == 1:
                return old
            return {"status": "done", "log": _AUDIT}
        raise AssertionError(endpoint)

    mock_api.get = AsyncMock(side_effect=fake_get)
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "audit-job-42"})
    result = await opn_firmware_cve_audit(mock_ctx, max_checks=1)
    assert result["state"] == "complete"
    assert result["assessment"] == "vulnerabilities_found"
    assert result["job_id"] == "audit-job-42"
    mock_api.post.assert_awaited_once_with("firmware.audit")


async def test_stale_done_log_cannot_be_reported_clean(mock_api, mock_ctx):
    mock_api.get = AsyncMock(
        side_effect=lambda endpoint: (
            {"status": "idle"} if endpoint == "firmware.running" else {"status": "done", "log": _CLEAN}
        )
    )
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "scan-stale"})
    result = await opn_firmware_cve_audit(mock_ctx, max_checks=1)
    assert result["state"] == "running"
    assert "assessment" not in result
    second = await opn_firmware_cve_audit_result(mock_ctx, job_id="scan-stale", max_checks=1)
    assert second["state"] == "running"
    assert "assessment" not in second


async def test_busy_backend_never_starts_second_audit(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"status": "busy"})
    mock_api.post = AsyncMock()
    result = await opn_firmware_cve_audit(mock_ctx)
    assert result["state"] == "backend_busy"
    mock_api.post.assert_not_awaited()


async def test_scan_runs_to_completion_in_followup(mock_api, mock_ctx):
    old = {"status": "done", "log": "old log"}
    mock_api.get = AsyncMock(
        side_effect=[
            {"status": "idle"},
            old,
            {"status": "running", "log": _AUDIT_MARKER},
            {"status": "done", "log": _CLEAN},
        ]
    )
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "scan-new"})
    start = await opn_firmware_cve_audit(mock_ctx, max_checks=1)
    assert start["state"] == "running"
    result = await opn_firmware_cve_audit_result(mock_ctx, job_id="scan-new", max_checks=1)
    assert result["state"] == "complete"
    assert result["assessment"] == "clean"
    mock_api.post.assert_awaited_once()


async def test_running_scan_cannot_be_started_twice(mock_api, mock_ctx):
    mock_api.get = AsyncMock(
        side_effect=lambda endpoint: (
            {"status": "idle"} if endpoint == "firmware.running" else {"status": "running", "log": ""}
        )
    )
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "pending-job"})
    first = await opn_firmware_cve_audit(mock_ctx, max_checks=1)
    second = await opn_firmware_cve_audit(mock_ctx, max_checks=1)
    assert first["state"] == "running"
    assert second["state"] == "already_running"
    mock_api.post.assert_awaited_once()


async def test_cannot_read_old_or_other_site_job(mock_api, mock_ctx):
    result = await opn_firmware_cve_audit_result(mock_ctx, job_id="nonexistent")
    assert result["state"] == "no_matching_session"


async def test_different_firmware_job_not_accepted_as_cve_scan(mock_api, mock_ctx):
    old = {"status": "done", "log": "old"}
    mock_api.get = AsyncMock(
        side_effect=[
            {"status": "idle"},
            old,
            {"status": "done", "log": "Firmware update finished\n***DONE***"},
        ]
    )
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "scan-456"})
    result = await opn_firmware_cve_audit(mock_ctx, max_checks=1)
    assert result["state"] == "inconclusive"
    assert "assessment" not in result


async def test_transient_outage_preserves_session(mock_api, mock_ctx):
    mock_api.get = AsyncMock(
        side_effect=[
            {"status": "idle"},
            {"status": "error", "log": ""},
            TimeoutError("temporary timeout"),
        ]
    )
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "scan-789"})
    result = await opn_firmware_cve_audit(mock_ctx, max_checks=1)
    assert result["state"] == "temporarily_unreachable"
    assert result["job_id"] == "scan-789"


async def test_invalid_interval_cannot_trigger_audit(mock_api, mock_ctx):
    mock_api.post = AsyncMock()
    with pytest.raises(ValueError):
        await opn_firmware_cve_audit(mock_ctx, max_checks=100)
    mock_api.post.assert_not_awaited()


async def test_polling_is_bounded(mock_api, mock_ctx):
    mock_api.get = AsyncMock(
        side_effect=lambda endpoint: (
            {"status": "idle"} if endpoint == "firmware.running" else {"status": "running", "log": ""}
        )
    )
    mock_api.post = AsyncMock(return_value={"status": "ok", "msg_uuid": "scan-poll"})
    with patch("opnsense_mcp.tools.firmware_cve.asyncio.sleep", new_callable=AsyncMock) as sleeping:
        result = await opn_firmware_cve_audit(mock_ctx, max_checks=3, poll_interval_seconds=1)
    assert result["state"] == "running"
    assert sleeping.await_count == 2
    assert mock_api.get.await_count == 5  # running + baseline + three progress samples
