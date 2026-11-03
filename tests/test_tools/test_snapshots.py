"""Unit tests for individual ZFS boot-environment MCP tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import WriteDisabledError
from opnsense_mcp.tools.snapshots import (
    opn_create_snapshot,
    opn_get_snapshot,
    opn_list_snapshots,
    opn_snapshot_supported,
)


async def test_snapshot_support_is_read_only(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"supported": True})
    result = await opn_snapshot_supported(mock_ctx)
    assert result == {"supported": True}
    mock_api.get.assert_awaited_once_with("snapshots.is_supported")


async def test_list_snapshots_is_read_only(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"rows": [{"name": "26.7.8_2"}]})
    result = await opn_list_snapshots(mock_ctx)
    assert result["rows"][0]["name"] == "26.7.8_2"
    mock_api.get.assert_awaited_once_with("snapshots.search")


async def test_get_snapshot_validates_uuid(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"name": "26.7.8_2"})
    assert await opn_get_snapshot(mock_ctx, "bad-id") == {"error": "Invalid snapshot UUID"}
    mock_api.get.assert_not_awaited()
    result = await opn_get_snapshot(mock_ctx, "123e4567-e89b-12d3-a456-426614174000")
    assert result["name"] == "26.7.8_2"
    mock_api.get.assert_awaited_once_with(
        "snapshots.get", path_suffix="123e4567-e89b-12d3-a456-426614174000"
    )


async def test_snapshot_creation_is_denied_in_read_only_mode(mock_api, mock_ctx):
    mock_api.get = AsyncMock()
    mock_api.post = AsyncMock()
    with pytest.raises(WriteDisabledError):
        await opn_create_snapshot(mock_ctx, name="26.7.8_2")
    mock_api.get.assert_not_awaited()
    mock_api.post.assert_not_awaited()


async def test_snapshot_creation_requires_zfs(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"supported": False})
    mock_api_writes.post = AsyncMock()
    result = await opn_create_snapshot(mock_ctx_writes, name="26.7.8_2")
    assert "error" in result
    mock_api_writes.post.assert_not_awaited()


async def test_snapshot_creation_is_primitive_without_activation(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"supported": True})
    mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
    result = await opn_create_snapshot(mock_ctx_writes, name="26.7.8_2")
    assert result == {"status": "ok"}
    mock_api_writes.get.assert_awaited_once_with("snapshots.is_supported")
    mock_api_writes.post.assert_awaited_once_with("snapshots.add", {"name": "26.7.8_2", "note": ""})


@pytest.mark.parametrize("name", [".", "..", "name with spaces", "../tmp", "a" * 81])
async def test_snapshot_name_rejected_before_network(mock_api_writes, mock_ctx_writes, name):
    mock_api_writes.get = AsyncMock()
    mock_api_writes.post = AsyncMock()
    result = await opn_create_snapshot(mock_ctx_writes, name=name)
    assert "error" in result
    mock_api_writes.get.assert_not_awaited()
    mock_api_writes.post.assert_not_awaited()
