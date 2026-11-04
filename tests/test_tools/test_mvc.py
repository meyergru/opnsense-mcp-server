"""Single-site MVC CRUD tests, especially WireGuard peer membership preservation."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import OperationEffect, WriteDisabledError, operation_effect
from opnsense_mcp.mvc_catalog import MVC_ENDPOINTS, MVC_GETS, MVC_SEARCHES, MVC_WRITES, RESOURCES
from opnsense_mcp.tools.mvc import (
    _sanitize,
    opn_kea_add,
    opn_kea_list,
    opn_mvc_get_settings,
    opn_mvc_patch_settings,
    opn_radvd_toggle,
    opn_service_apply,
    opn_unbound_patch,
    opn_wireguard_add_peer,
    opn_wireguard_generate_psk,
    opn_wireguard_get_peer,
    opn_wireguard_patch_peer,
)

PEER = "11111111-1111-4111-8111-111111111111"
INSTANCE = "22222222-2222-4222-8222-222222222222"


def test_all_approved_mvc_endpoints_are_in_global_registry():
    from opnsense_mcp.api_client import ENDPOINT_REGISTRY

    assert len(MVC_ENDPOINTS) >= 90
    for endpoint, paths in MVC_ENDPOINTS.items():
        assert ENDPOINT_REGISTRY[endpoint] == paths
        assert (
            endpoint in MVC_GETS or endpoint in MVC_SEARCHES or ("POST", endpoint) in MVC_WRITES
        )
        if endpoint in MVC_GETS:
            assert operation_effect("GET", endpoint) is OperationEffect.READ
        elif endpoint in MVC_SEARCHES:
            assert operation_effect("POST", endpoint) is OperationEffect.READ
        else:
            assert operation_effect("POST", endpoint) is OperationEffect.WRITE
    assert {"kea", "radvd", "unbound", "wireguard"} <= set(RESOURCES)


async def test_wireguard_psk_is_kept_secret_and_opaque_reference_is_reusable(mock_ctx):
    from opnsense_mcp.tools.mvc import _psk_from_ref

    result = await opn_wireguard_generate_psk(mock_ctx)
    reference = result["psk_ref"]
    assert "psk" not in result
    assert _psk_from_ref(reference) == _psk_from_ref(reference)
    assert len(_psk_from_ref(reference)) == 44
    assert result["expires_in_seconds"] == 1800


async def test_wireguard_psk_patch_preserves_original_instance_associations(mock_api_writes, mock_ctx_writes):
    from opnsense_mcp.tools.mvc import _psk_from_ref

    opaque = await opn_wireguard_generate_psk(mock_ctx_writes)
    reference = opaque["psk_ref"]
    mock_api_writes.get = AsyncMock(
        return_value={"client": {
            "name": "peer-A", "pubkey": "PUBLICKEY", "servers": {
                INSTANCE: {"selected": 1, "value": "Existing Site-to-Site"}
            }, "psk": "OLD_SECRET", "tunneladdress": "10.10.0.0/24",
        }}
    )
    mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
    result = await opn_wireguard_patch_peer(
        mock_ctx_writes, uuid=PEER, changes={}, psk_ref=reference
    )
    assert result["applied"] is False
    assert mock_api_writes.get.await_count == 1
    mock_api_writes.post.assert_awaited_once_with(
        "mvc.wireguard.peer.set",
        {"client": {"servers": INSTANCE, "psk": _psk_from_ref(reference)}},
        path_suffix=PEER,
    )
    assert "psk" not in str(result).lower()
    # Apply is separate: no unexpected service reconfigure in the same call.
    assert mock_api_writes.post.await_count == 1


async def test_wireguard_patch_rejects_missing_servers_relation_before_write(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"client": {"name": "old"}})
    mock_api_writes.post = AsyncMock()
    with pytest.raises(ValueError, match="servers relation"):
        await opn_wireguard_patch_peer(mock_ctx_writes, uuid=PEER, changes={"name": "new"})
    mock_api_writes.post.assert_not_awaited()


async def test_wireguard_patch_rejects_unknown_object_instead_of_upserting(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={})
    mock_api_writes.post = AsyncMock()
    with pytest.raises(ValueError, match="refusing implicit upsert"):
        await opn_wireguard_patch_peer(mock_ctx_writes, uuid=PEER, changes={"name": "renamed"})
    mock_api_writes.post.assert_not_awaited()


async def test_read_only_blocks_wireguard_patch_before_http(mock_api, mock_ctx):
    mock_api.get = AsyncMock()
    mock_api.post = AsyncMock()
    with pytest.raises(WriteDisabledError):
        await opn_wireguard_patch_peer(mock_ctx, uuid=PEER, changes={"name": "new"})
    mock_api.get.assert_not_awaited()
    mock_api.post.assert_not_awaited()


async def test_wireguard_add_peers_preserves_existing_server_and_refuses_bad_server(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(
        side_effect=[
            {"server": {"name": "wg-existing", "privkey": "SHOULD_NOT_LEAK"}},
            {"client": {"name": "", "servers": {}, "pubkey": "", "tunneladdress": ""}},
        ]
    )
    mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": PEER})
    result = await opn_wireguard_add_peer(
        mock_ctx_writes,
        fields={"name": "B", "pubkey": "A_PUBLIC_KEY", "servers": INSTANCE, "tunneladdress": "10.20.0.0/24"},
    )
    assert result["uuid"] == PEER
    mock_api_writes.post.assert_awaited_once()
    assert mock_api_writes.post.await_args.args[0] == "mvc.wireguard.peer.add"
    assert mock_api_writes.post.await_args.args[1]["client"]["servers"] == INSTANCE


async def test_wireguard_get_never_exposes_psk_or_privkey(mock_api, mock_ctx):
    mock_api.get = AsyncMock(return_value={"client": {"name": "test", "psk": "s", "privkey": "secret", "pubkey": "public"}})
    result = await opn_wireguard_get_peer(mock_ctx, uuid=PEER)
    assert result["fields"] == {"name": "test", "pubkey": "public"}
    assert "secret" not in str(result)


async def test_kea_add_validates_template_and_never_applies(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"reservation": {"hw_address": "", "ip_address": ""}})
    mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": PEER})
    r = await opn_kea_add(
        mock_ctx_writes, resource="reservation4",
        fields={"hw_address": "aa:bb:cc:dd:ee:ff", "ip_address": "192.0.2.14"},
    )
    assert r["result"] == "saved"
    mock_api_writes.post.assert_awaited_once()
    assert mock_api_writes.post.await_args.args[0] == "mvc.kea.reservation.get".replace(".get", ".add")


async def test_kea_list_uses_explicit_registered_search(mock_api, mock_ctx):
    mock_api.post = AsyncMock(return_value={"rows": []})
    await opn_kea_list(mock_ctx, resource="pd_pool6")
    mock_api.post.assert_awaited_once()
    assert mock_api.post.await_args.args[0] == "mvc.kea.pdpool.get".replace(".get", ".search")


async def test_unbound_patch_is_single_object_no_auto_apply(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"acl": {"name": "old", "action": "allow"}})
    mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
    result = await opn_unbound_patch(mock_ctx_writes, "acl", PEER, {"action": "deny"})
    assert result["applied"] is False
    mock_api_writes.post.assert_awaited_once_with(
        "mvc.unbound.acl.set", {"acl": {"action": "deny"}}, path_suffix=PEER
    )


async def test_radvd_toggle_is_not_automatic_reconfigure(mock_api_writes, mock_ctx_writes):
    mock_api_writes.post = AsyncMock(return_value={"result": "Disabled"})
    await opn_radvd_toggle(mock_ctx_writes, uuid=PEER, enabled=False)
    mock_api_writes.post.assert_awaited_once_with(
        "mvc.radvd.entry.toggle", path_suffix=f"{PEER}/0"
    )


async def test_apply_is_explicit_single_service(mock_api_writes, mock_ctx_writes):
    mock_api_writes.post = AsyncMock(return_value={"result": "ok"})
    result = await opn_service_apply(mock_ctx_writes, service="wireguard")
    assert result["service"] == "wireguard"
    mock_api_writes.post.assert_awaited_once_with("mvc.service.wireguard.reconfigure")


async def test_global_settings_read_and_patch_are_individual(mock_api_writes, mock_ctx_writes):
    mock_api_writes.get = AsyncMock(return_value={"dhcpv6": {"general": {"enabled": "1"}}})
    mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
    before = await opn_mvc_get_settings(mock_ctx_writes, subsystem="kea_dhcpv6")
    assert before["settings"]["general"]["enabled"] == "1"
    result = await opn_mvc_patch_settings(
        mock_ctx_writes, subsystem="kea_dhcpv6", changes={"general": {"enabled": "0"}}
    )
    assert result["applied"] is False
    mock_api_writes.post.assert_awaited_once_with(
        "mvc.settings.kea_dhcpv6.set", {"dhcpv6": {"general": {"enabled": "0"}}}
    )


def test_sanitize_masks_secrets_recursively():
    data = {"server": {"privkey": "SECRET", "psk": "SECRET2", "pubkey": "PUBLIC"}, "rows": [{"api_secret": "SECRET3"}]}
    assert _sanitize(data) == {"server": {"pubkey": "PUBLIC"}, "rows": [{}]}
