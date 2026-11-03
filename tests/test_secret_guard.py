"""Tests for safe remote tool responses."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opnsense_mcp.secret_guard import contains_secret_fields
from opnsense_mcp.tools.system import opn_download_config, opn_get_config_section


@pytest.mark.parametrize(
    "payload",
    [
        {"vpn": {"private_key": "very-secret"}},
        {"DDNS": [{"password": "not-for-llm"}]},
        {"result": {"api-secret": "value"}},
        [{"authentication": {"pre_shared_key": "value"}}],
        {"token": "[REDACTED]"},
    ],
)
def test_reject_sensitive_field_names(payload):
    assert contains_secret_fields(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"rows": [{"uuid": "x", "description": "a rule", "action": "pass"}]},
        {"interfaces": {"lan": {"ipaddr": "192.168.1.1"}}},
        {"status": "running", "count": 42},
        None,
    ],
)
def test_accept_non_secret_structures(payload):
    assert not contains_secret_fields(payload)


@pytest.mark.asyncio
async def test_http_download_config_rejected_before_api_call():
    with patch.dict("os.environ", {"OPNSENSE_MCP_TRANSPORT": "http"}):
        result = await opn_download_config(MagicMock())
    assert result.get("error") == "Raw configuration export is disabled for remote MCP clients"


@pytest.mark.asyncio
async def test_http_config_section_rejected_before_api_call():
    with patch.dict("os.environ", {"OPNSENSE_MCP_TRANSPORT": "http"}):
        result = await opn_get_config_section(MagicMock(), section="interfaces")
    assert result.get("error") == "Raw configuration sections are disabled for remote MCP clients"
