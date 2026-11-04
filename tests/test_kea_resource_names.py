"""Regression tests for discoverable Kea reservation tools and exact resource names."""

from __future__ import annotations

from typing import get_args, get_type_hints
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.mvc_catalog import KeaResourceName, RESOURCES
from opnsense_mcp.tools.mvc import (
    _resource,
    opn_kea_add,
    opn_kea_delete,
    opn_kea_get,
    opn_kea_list,
    opn_kea_patch,
)

UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def test_kea_literal_matches_registered_resources():
    assert set(get_args(KeaResourceName)) == set(RESOURCES["kea"])


@pytest.mark.parametrize("tool", [opn_kea_list, opn_kea_get, opn_kea_add, opn_kea_patch, opn_kea_delete])
def test_kea_tools_advertise_exact_resource_names(tool):
    advertised = get_args(get_type_hints(tool)["resource"])
    assert set(advertised) == set(RESOURCES["kea"])


def test_unknown_kea_resource_explains_valid_values():
    with pytest.raises(ValueError) as exc:
        _resource("kea", "reservations")
    message = str(exc.value)
    assert "Unsupported kea resource: reservations" in message
    assert "reservation4" in message
    assert "reservation6" in message


async def test_search_dhcpv4_reservations_by_hostname(mock_api, mock_ctx):
    row = {"uuid": UUID, "hostname": "docker", "hw_address": "aa:bb:cc:dd:ee:ff"}
    mock_api.post = AsyncMock(return_value={"rows": [row], "rowCount": 1})
    result = await opn_kea_list(mock_ctx, resource="reservation4", search="docker")
    mock_api.post.assert_awaited_once_with(
        "mvc.kea.reservation4.search",
        {"current": 1, "rowCount": 100, "searchPhrase": "docker"},
    )
    assert result["rows"][0]["uuid"] == UUID


async def test_kea_reservation_mac_patch_is_targeted_and_not_applied(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(
        return_value={"reservation": {"hostname": "docker", "ip_address": "192.0.2.40", "hw_address": "aa:bb:cc:dd:ee:ff"}}
    )
    mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
    result = await opn_kea_patch(
        mock_ctx_writes,
        resource="reservation4",
        uuid=UUID,
        changes={"hw_address": "c6:a5:6c:29:90:21"},
    )
    mock_api_writes.post.assert_awaited_once_with(
        "mvc.kea.reservation4.set",
        {"reservation": {"hw_address": "c6:a5:6c:29:90:21"}},
        path_suffix=UUID,
    )
    assert result["applied"] is False
