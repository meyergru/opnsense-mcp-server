"""Security regression tests for the central API read-only operation gate."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from opnsense_mcp.api_client import ENDPOINT_REGISTRY, READ_ONLY_POST_ENDPOINTS, WriteDisabledError


def test_all_readonly_post_operations_are_known():
    assert READ_ONLY_POST_ENDPOINTS <= ENDPOINT_REGISTRY.keys()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint",
    [
        "firewall.add_rule",
        "firewall.apply",
        "firewall.toggle_rule",
        "unbound.service.reconfigure",
        "unbound.set_dnsbl",
        "diagnostics.ping.start",
        "dnsmasq.settings.add_range",
        "dyndns.accounts.del",
        "mdnsrepeater.service.start",
    ],
)
async def test_mutating_post_rejected_before_network(mock_api, endpoint):
    with pytest.raises(WriteDisabledError, match="read-only mode"):
        await mock_api.post(endpoint)
    mock_api._client.post.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint",
    [
        "firewall.search_rule",
        "core.service.search",
        "firmware.status",
        "kea.leases4.search",
        "diagnostics.firewall.query_states",
        "haproxy.settings.search_frontends",
    ],
)
async def test_explicit_read_search_post_allowed(mock_api, endpoint):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"rows": [], "total": 0}
    mock_api._client.post.return_value = response
    result = await mock_api.post(endpoint, {"rowCount": 10})
    assert result == {"rows": [], "total": 0}
    mock_api._client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_write_enabled_still_uses_existing_write_path(mock_api_writes):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"result": "ok"}
    mock_api_writes._client.post.return_value = response
    result = await mock_api_writes.post("unbound.service.reconfigure")
    assert result == {"result": "ok"}
    mock_api_writes._client.post.assert_awaited_once()
