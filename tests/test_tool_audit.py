"""Safe and bounded logging of tool outcomes without arguments or secrets."""
from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from opnsense_mcp.tool_audit import ToolAuditMiddleware, _label


def test_label_blocks_untrusted_text():
    assert _label("opnsense.mgsoft", "(invalid)") == "opnsense.mgsoft"
    assert _label("attack\nINJECT=secret", "(invalid)") == "(invalid)"
    assert _label("", "(default)") == "(default)"


@pytest.mark.asyncio
async def test_all_mode_records_tool_metadata_but_not_arguments(caplog):
    middleware = ToolAuditMiddleware("all")
    context = SimpleNamespace(message=SimpleNamespace(
        name="opn_system_status",
        arguments={"site": "opnsense.mgsoft", "password": "topsecret"},
    ))
    result = SimpleNamespace(is_error=False)
    async def call_next(_context):
        return result
    with caplog.at_level(logging.INFO, logger="opnsense_mcp.audit"):
        assert await middleware.on_call_tool(context, call_next) is result
    assert "tool=opn_system_status" in caplog.text
    assert "site=opnsense.mgsoft" in caplog.text
    assert "result=success" in caplog.text
    assert "topsecret" not in caplog.text


@pytest.mark.asyncio
async def test_errors_mode_logs_exceptions_without_exception_details(caplog):
    middleware = ToolAuditMiddleware("errors")
    context = SimpleNamespace(message=SimpleNamespace(name="opn_ping", arguments={"site": "one"}))
    async def call_next(_context):
        raise RuntimeError("SECRET=not-for-logs")
    with caplog.at_level(logging.WARNING, logger="opnsense_mcp.audit"):
        with pytest.raises(RuntimeError):
            await middleware.on_call_tool(context, call_next)
    assert "result=error" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "not-for-logs" not in caplog.text


@pytest.mark.asyncio
async def test_none_mode_is_silent(caplog):
    middleware = ToolAuditMiddleware("none")
    context = SimpleNamespace(message=SimpleNamespace(name="opn_ping", arguments={}))
    async def call_next(_context):
        return SimpleNamespace(is_error=False)
    with caplog.at_level(logging.DEBUG, logger="opnsense_mcp.audit"):
        await middleware.on_call_tool(context, call_next)
    assert "tool=opn_ping" not in caplog.text
