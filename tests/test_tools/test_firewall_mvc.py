"""Firewall 26.7 controllers: fixed catalog, guarded CRUD and explicit apply.

All tests use mocked site API clients. No real firewall is modified.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.api_client import (
    ENDPOINT_REGISTRY,
    OperationEffect,
    WriteDisabledError,
    operation_effect,
)
from opnsense_mcp.firewall_catalog import (
    FIREWALL_ENDPOINTS,
    FIREWALL_GETS,
    FIREWALL_SEARCHES,
    FIREWALL_WRITES,
    RESOURCES,
)
from opnsense_mcp.tools.firewall_mvc import (
    opn_firewall_alias_references,
    opn_firewall_apply_changes,
    opn_firewall_create_object,
    opn_firewall_delete_object,
    opn_firewall_get_object,
    opn_firewall_legacy_rule_counts,
    opn_firewall_list_objects,
    opn_firewall_move_rule,
    opn_firewall_patch_object,
    opn_firewall_set_enabled,
    opn_firewall_set_logging,
)

RULE = "11111111-1111-4111-8111-111111111111"
BEFORE = "22222222-2222-4222-8222-222222222222"


def test_every_firewall_endpoint_is_registered_and_explicitly_classified():
    assert len(FIREWALL_ENDPOINTS) == 69
    assert set(RESOURCES) == {"filter", "dnat", "snat", "one_to_one", "npt", "alias", "category", "group"}
    for endpoint, paths in FIREWALL_ENDPOINTS.items():
        assert ENDPOINT_REGISTRY[endpoint] == paths
        if endpoint in FIREWALL_GETS:
            assert operation_effect("GET", endpoint) is OperationEffect.READ
        elif endpoint in FIREWALL_SEARCHES:
            assert operation_effect("POST", endpoint) is OperationEffect.READ
        else:
            assert ("POST", endpoint) in FIREWALL_WRITES
            assert operation_effect("POST", endpoint) is OperationEffect.WRITE


@pytest.mark.parametrize(
    "kind,controller", [
        ("filter", "filter"), ("dnat", "d_nat"), ("snat", "source_nat"),
        ("one_to_one", "one_to_one"), ("npt", "npt"),
    ]
)
async def test_firewall_search_controller_routes(mock_api, mock_ctx, kind, controller):
    mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
    assert (await opn_firewall_list_objects(mock_ctx, kind))["rows"] == []
    mock_api.post.assert_awaited_once_with(
        f"fw26.{kind}.search", {"current": 1, "rowCount": 100, "searchPhrase": ""}
    )
    assert ENDPOINT_REGISTRY[f"fw26.{kind}.search"][0] == f"firewall/{controller}/searchRule"


async def test_firewall_get_one_object(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"rule": {"description": "test"}})
    assert (await opn_firewall_get_object(mock_ctx, "dnat", RULE))["rule"]["description"] == "test"
    mock_api.get.assert_awaited_once_with("fw26.dnat.get", path_suffix=RULE)


async def test_firewall_add_validates_model_then_stages(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"rule": {"description": "", "enabled": ""}})
    mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": RULE})
    result = await opn_firewall_create_object(
        mock_ctx_writes, "npt", {"description": "A-to-B", "enabled": "1"}
    )
    assert result["applied"] is False
    mock_api_writes.post.assert_awaited_once_with(
        "fw26.npt.add", {"rule": {"description": "A-to-B", "enabled": "1"}}
    )


async def test_firewall_add_rejects_unsupported_field(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"rule": {"description": ""}})
    mock_api_writes.post = AsyncMock()
    with pytest.raises(ValueError, match="Unsupported fields"):
        await opn_firewall_create_object(mock_ctx_writes, "npt", {"unknown": "1"})
    mock_api_writes.post.assert_not_awaited()


async def test_firewall_patch_preserves_unmentioned_fields(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(
        return_value={"rule": {"description": "old", "interface": "wan", "source_net": "10.0.0.0/8"}}
    )
    mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
    result = await opn_firewall_patch_object(
        mock_ctx_writes, "filter", RULE, {"description": "new"}
    )
    assert result["changed_fields"] == ["description"]
    assert result["applied"] is False
    mock_api_writes.post.assert_awaited_once_with(
        "fw26.filter.set", {"rule": {"description": "new"}}, path_suffix=RULE
    )


async def test_firewall_rejects_legacy_rules_before_patch_delete(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"rule": {"legacy": "1", "description": "legacy"}})
    mock_api_writes.post = AsyncMock()
    with pytest.raises(ValueError, match="Legacy"):
        await opn_firewall_patch_object(mock_ctx_writes, "filter", RULE, {"description": "changed"})
    with pytest.raises(ValueError, match="Legacy"):
        await opn_firewall_delete_object(mock_ctx_writes, "filter", RULE)
    mock_api_writes.post.assert_not_awaited()


async def test_firewall_rejects_generated_nat_rule_before_delete(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"rule": {"automatic": "1"}})
    mock_api_writes.post = AsyncMock()
    with pytest.raises(ValueError, match="Automatically"):
        await opn_firewall_delete_object(mock_ctx_writes, "dnat", RULE)
    mock_api_writes.post.assert_not_awaited()


async def test_firewall_delete_is_single_object_with_no_apply(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"rule": {"description": "one"}})
    mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
    result = await opn_firewall_delete_object(mock_ctx_writes, "snat", RULE)
    assert result["applied"] is False
    mock_api_writes.post.assert_awaited_once_with("fw26.snat.del", path_suffix=RULE)


@pytest.mark.parametrize(
    "kind,enabled,expected", [
        ("filter", True, "1"), ("filter", False, "0"),
        ("dnat", True, "0"), ("dnat", False, "1"),
        ("snat", True, "1"), ("one_to_one", False, "0"),
        ("npt", True, "1"), ("alias", False, "0"),
    ]
)
async def test_set_enabled_explicitly_and_invert_only_dnat(mock_api_writes, mock_ctx_writes, kind, enabled, expected):
    key = "alias" if kind == "alias" else "rule"
    mock_api_writes.get = AsyncMock(return_value={key: {"enabled": "0"}})
    mock_api_writes.post = AsyncMock(return_value={"result": "Enabled"})
    result = await opn_firewall_set_enabled(mock_ctx_writes, kind, RULE, enabled)
    assert result["enabled_requested"] is enabled
    assert result["applied"] is False
    mock_api_writes.post.assert_awaited_once_with(
        f"fw26.{kind}.toggle", path_suffix=f"{RULE}/{expected}"
    )


async def test_category_cannot_be_toggled(mock_ctx_writes):
    with pytest.raises(ValueError, match="no enable"):
        await opn_firewall_set_enabled(mock_ctx_writes, "category", RULE, True)


async def test_logging_is_explicit_with_no_apply(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"rule": {"description": "A"}})
    mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
    result = await opn_firewall_set_logging(mock_ctx_writes, "filter", RULE, True)
    assert result["applied"] is False
    mock_api_writes.post.assert_awaited_once_with("fw26.filter.log", path_suffix=f"{RULE}/1")


async def test_move_requires_valid_uuids_and_same_type(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"rule": {"description": "A"}})
    mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
    result = await opn_firewall_move_rule(mock_ctx_writes, "one_to_one", [RULE], BEFORE)
    assert result["applied"] is False
    mock_api_writes.post.assert_awaited_once_with(
        "fw26.one_to_one.move", path_suffix=f"{RULE}/{BEFORE}"
    )


async def test_move_rejects_same_source_and_target(mock_api_writes, mock_ctx_writes):
    mock_api_writes.post = AsyncMock()
    with pytest.raises(ValueError, match="Select 1-50 distinct"):
        await opn_firewall_move_rule(mock_ctx_writes, "filter", [RULE], RULE)
    mock_api_writes.post.assert_not_awaited()


async def test_apply_requires_confirmation_even_with_site_writes(mock_api_writes, mock_ctx_writes):
    mock_api_writes.post = AsyncMock()
    result = await opn_firewall_apply_changes(mock_ctx_writes)
    assert "error" in result
    mock_api_writes.post.assert_not_awaited()


async def test_apply_calls_filter_apply_only_with_confirmation(mock_api_writes, mock_ctx_writes, mock_config_cache):
    mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
    result = await opn_firewall_apply_changes(mock_ctx_writes, confirm=True)
    assert result["applied"] is True
    assert result["rollback_guaranteed"] is False
    mock_api_writes.post.assert_awaited_once_with("fw26.filter.apply")


async def test_firewall_write_denied_before_network(mock_api, mock_ctx):
    mock_api.get = AsyncMock()
    mock_api.post = AsyncMock()
    with pytest.raises(WriteDisabledError):
        await opn_firewall_delete_object(mock_ctx, "filter", RULE)
    mock_api.get.assert_not_awaited()
    mock_api.post.assert_not_awaited()


async def test_firewall_alias_reference_query_is_read_only(mock_api, mock_ctx):
    mock_api.post = AsyncMock(return_value={"matches": ["internal"]})
    result = await opn_firewall_alias_references(mock_ctx, "192.0.2.5")
    assert result["matches"] == ["internal"]
    mock_api.post.assert_awaited_once_with("fw26.alias.references", {"ip": "192.0.2.5"})


async def test_firewall_migration_counts_are_read_only(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"count": 4})
    result = await opn_firewall_legacy_rule_counts(mock_ctx)
    assert set(result) == {"legacy_rules", "legacy_outbound_nat"}
    assert mock_api.get.await_count == 2


@pytest.mark.parametrize("method,key,path", [
    ("POST", "fw26.filter.add", "/firewall/filter/add_rule"),
    ("POST", "fw26.dnat.toggle", "/firewall/d_nat/toggle_rule"),
    ("GET", "fw26.snat.get", "/firewall/source_nat/get_rule"),
    ("POST", "fw26.one_to_one.search", "/firewall/one_to_one/search_rule"),
    ("POST", "fw26.npt.move", "/firewall/npt/move_rule_before"),
])
async def test_real_client_routes_are_resolvable(
    mock_api_writes, method, key, path
):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"result": "ok"}
    method_call = mock_api_writes._client.post if method == "POST" else mock_api_writes._client.get
    method_call.return_value = response
    mock_api_writes._use_snake_case = True
    if method == "POST":
        await mock_api_writes.post(key)
        method_call.assert_awaited_once_with(path, json=None)
    else:
        await mock_api_writes.get(key)
        method_call.assert_awaited_once_with(path)
