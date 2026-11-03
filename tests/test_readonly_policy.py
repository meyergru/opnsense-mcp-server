"""Security regression tests for the central API read-only operation gate."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from opnsense_mcp.api_client import (
    ENDPOINT_REGISTRY,
    DIAGNOSTIC_OPERATIONS,
    READ_ONLY_GET_ENDPOINTS,
    READ_ONLY_POST_ENDPOINTS,
    OperationEffect,
    WriteDisabledError,
    operation_effect,
)


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


def test_explicit_operation_classification_is_independent_of_http_method():
    assert operation_effect("GET", "firmware.status") is OperationEffect.READ
    assert operation_effect("POST", "firmware.status") is OperationEffect.DIAGNOSTIC
    assert operation_effect("POST", "firewall.search_rule") is OperationEffect.READ
    assert operation_effect("GET", "firewall.add_rule") is OperationEffect.WRITE
    assert operation_effect("POST", "firewall.add_rule") is OperationEffect.WRITE
    assert operation_effect("GET", "some.new.operation") is OperationEffect.WRITE
    assert ("POST", "firmware.status") in DIAGNOSTIC_OPERATIONS
    assert READ_ONLY_GET_ENDPOINTS <= ENDPOINT_REGISTRY.keys() | {
        f"haproxy.settings.get_{x}"
        for x in (
            "frontend", "backend", "server", "action", "acl",
            "healthcheck", "errorfile", "resolver", "mailer",
        )
    }


@pytest.mark.asyncio
async def test_get_to_mutating_operation_denied_before_network(mock_api):
    with pytest.raises(WriteDisabledError, match="read-only"):
        await mock_api.get("firewall.add_rule")
    mock_api._client.get.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_get_operation_denied_before_network(mock_api):
    from opnsense_mcp.api_client import ENDPOINT_REGISTRY

    ENDPOINT_REGISTRY["_test_get_unknown"] = ("test/operation", "test/operation")
    try:
        with pytest.raises(WriteDisabledError, match="read-only"):
            await mock_api.get("_test_get_unknown")
        mock_api._client.get.assert_not_awaited()
    finally:
        ENDPOINT_REGISTRY.pop("_test_get_unknown")


@pytest.mark.asyncio
async def test_get_text_to_mutating_operation_denied_before_network(mock_api):
    with pytest.raises(WriteDisabledError, match="read-only"):
        await mock_api.get_text("firewall.add_rule")
    mock_api._client.get.assert_not_awaited()
