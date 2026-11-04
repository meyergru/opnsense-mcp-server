"""Tests for service tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import WriteDisabledError
from opnsense_mcp.tools.services import (
    opn_add_ddns_account,
    opn_configure_mdns_repeater,
    opn_crowdsec_alerts,
    opn_crowdsec_status,
    opn_delete_ddns_account,
    opn_ddns_service_control,
    opn_ddns_service_status,
    opn_force_refresh_ddns_accounts,
    opn_get_ddns_account,
    opn_get_ddns_settings,
    opn_patch_ddns_settings,
    opn_set_ddns_account_enabled,
    opn_list_acme_certs,
    opn_list_cron_jobs,
    opn_list_ddns_accounts,
    opn_mdns_repeater_status,
    opn_reconfigure_ddclient,
    opn_update_ddns_account,
)


class TestOpnListAcmeCerts:
    """Tests for opn_list_acme_certs."""

    async def test_calls_acme_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_acme_certs(mock_ctx)
        mock_api.post.assert_called_once_with(
            "acmeclient.certs.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_phrase(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_acme_certs(mock_ctx, search="example.com")
        mock_api.post.assert_called_once_with(
            "acmeclient.certs.search",
            {"current": 1, "rowCount": 50, "searchPhrase": "example.com"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_acme_certs(mock_ctx, limit=800)
        mock_api.post.assert_called_once_with(
            "acmeclient.certs.search",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnListCronJobs:
    """Tests for opn_list_cron_jobs."""

    async def test_calls_cron_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_list_cron_jobs(mock_ctx)
        mock_api.post.assert_called_once_with(
            "cron.search_jobs",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_cron_jobs(mock_ctx, search="backup", limit=20)
        mock_api.post.assert_called_once_with(
            "cron.search_jobs",
            {"current": 1, "rowCount": 20, "searchPhrase": "backup"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_cron_jobs(mock_ctx, limit=501)
        mock_api.post.assert_called_once_with(
            "cron.search_jobs",
            {"current": 1, "rowCount": 500, "searchPhrase": ""},
        )


class TestOpnCrowdsecStatus:
    """Tests for opn_crowdsec_status."""

    _SEARCH_PARAMS = {"current": 1, "rowCount": 500, "searchPhrase": ""}

    async def test_returns_status_and_counts(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [{"id": "1", "type": "ban"}], "rowCount": 1},
                {"rows": [{"id": "a1"}], "rowCount": 1},
            ],
        )
        result = await opn_crowdsec_status(mock_ctx)
        mock_api.get.assert_called_once_with("crowdsec.service.status")
        mock_api.post.assert_any_call("crowdsec.decisions.search", self._SEARCH_PARAMS)
        mock_api.post.assert_any_call("crowdsec.alerts.search", self._SEARCH_PARAMS)
        assert result["service_status"] == "running"
        assert result["decisions_count"] == 1
        assert result["alerts_count"] == 1

    async def test_empty_decisions_and_alerts(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": [], "rowCount": 0},
                {"rows": [], "rowCount": 0},
            ],
        )
        result = await opn_crowdsec_status(mock_ctx)
        assert result["decisions_count"] == 0
        assert result["alerts_count"] == 0

    async def test_limits_decisions_to_20(self, mock_api, mock_ctx):
        many_decisions = [{"id": str(i)} for i in range(30)]
        mock_api.get = AsyncMock(return_value={"status": "running"})
        mock_api.post = AsyncMock(
            side_effect=[
                {"rows": many_decisions, "rowCount": 30},
                {"rows": [], "rowCount": 0},
            ],
        )
        result = await opn_crowdsec_status(mock_ctx)
        assert len(result["decisions"]) == 20
        assert result["decisions_count"] == 30


class TestOpnCrowdsecAlerts:
    """Tests for opn_crowdsec_alerts."""

    async def test_calls_alerts_search(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_crowdsec_alerts(mock_ctx)
        mock_api.post.assert_called_once_with(
            "crowdsec.alerts.search",
            {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )
        assert result == {"rows": [], "rowCount": 0}

    async def test_passes_search_and_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_crowdsec_alerts(mock_ctx, search="ssh", limit=20)
        mock_api.post.assert_called_once_with(
            "crowdsec.alerts.search",
            {"current": 1, "rowCount": 20, "searchPhrase": "ssh"},
        )

    async def test_limit_capped_at_500(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_crowdsec_alerts(mock_ctx, limit=999)
        call_args = mock_api.post.call_args[0][1]
        assert call_args["rowCount"] == 500


class TestDdnsPlugin:
    """Source-reviewed os-ddclient plugin contracts; no live firewall needed."""

    async def test_list_filters_credentials_and_keeps_real_hostnames_field(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={
            "rows": [{"uuid": "one", "hostnames": "a.example", "current_ip": "203.0.113.1",
                      "password": "secret", "%password": "marker", "token": "secret",
                      "secret_future_field": "leak"}], "rowCount": 1,
        })
        result = await opn_list_ddns_accounts(mock_ctx)
        assert result == {"rows": [
            {"uuid": "one", "hostnames": "a.example", "current_ip": "203.0.113.1"},
        ], "rowCount": 1}
        mock_api.post.assert_awaited_once_with(
            "dyndns.accounts.search", {"current": 1, "rowCount": 50, "searchPhrase": ""},
        )

    async def test_list_respects_search_and_bounded_limit(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_list_ddns_accounts(mock_ctx, search="example", limit=900)
        assert mock_api.post.call_args.args[1] == {
            "current": 1, "rowCount": 500, "searchPhrase": "example",
        }

    async def test_get_account_uses_get_item_and_redacts_secret_fields(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"account": {
            "hostnames": "a.example", "password": "DO-NOT-LEAK",
            "resourceId": "public-resource", "uuid": "account-1",
        }})
        result = await opn_get_ddns_account(mock_ctx, "account-1")
        assert result == {"uuid": "account-1", "account": {
            "hostnames": "a.example", "resourceId": "public-resource", "uuid": "account-1",
        }}
        mock_api.get.assert_awaited_once_with("dyndns.accounts.get_item", path_suffix="account-1")

    async def test_rejects_path_suffix_injection(self, mock_api, mock_ctx):
        with pytest.raises(ValueError, match="identifier"):
            await opn_get_ddns_account(mock_ctx, "../etc/passwd")
        mock_api.get.assert_not_awaited()

    async def test_add_stages_real_model_fields_only(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "new-uuid"})
        result = await opn_add_ddns_account(
            mock_ctx_writes, service="cloudflare", hostname="v6.example",
            checkip="web_cloudflare_ipv6", password="secret",
            ttl=300, force_ssl=True, description="IPv6 record",
        )
        mock_api_writes.post.assert_awaited_once()
        call = mock_api_writes.post.call_args
        assert call.args[0] == "dyndns.accounts.add"
        account = call.args[1]["account"]
        assert account["hostnames"] == "v6.example"
        assert "hostname" not in account
        assert account["checkip"] == "web_cloudflare_ipv6"
        assert account["ttl"] == "300"
        assert account["force_ssl"] == "1"
        assert account["password"] == "secret"
        assert result == {"result": "saved", "uuid": "new-uuid", "applied": False}
        assert "secret" not in str(result)

    async def test_add_validates_interface_and_bounds(self, mock_api_writes, mock_ctx_writes):
        with pytest.raises(ValueError, match="interface"):
            await opn_add_ddns_account(mock_ctx_writes, "cloudflare", "a.example", checkip="if")
        with pytest.raises(ValueError, match="ttl"):
            await opn_add_ddns_account(mock_ctx_writes, "cloudflare", "a.example", ttl=0)
        mock_api_writes.post.assert_not_awaited()

    async def test_add_requires_writes(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_add_ddns_account(mock_ctx, "cloudflare", "a.example")

    async def test_update_partial_and_never_apply(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        result = await opn_update_ddns_account(
            mock_ctx_writes, uuid="test-uuid", hostname="changed.example",
            password="new-secret", enabled=False,
        )
        mock_api_writes.post.assert_awaited_once_with(
            "dyndns.accounts.set",
            {"account": {"hostnames": "changed.example", "password": "new-secret", "enabled": "0"}},
            path_suffix="test-uuid",
        )
        assert result == {"result": "saved", "uuid": "test-uuid", "applied": False}
        assert "new-secret" not in str(result)

    async def test_noop_update_skips_network(self, mock_api, mock_ctx):
        result = await opn_update_ddns_account(mock_ctx, "test-uuid")
        assert result["result"] == "unchanged"
        mock_api.post.assert_not_awaited()

    async def test_toggle_is_idempotent(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.get = AsyncMock(return_value={"account": {"enabled": "1"}})
        result = await opn_set_ddns_account_enabled(mock_ctx_writes, "test-uuid", True)
        assert result["result"] == "unchanged"
        mock_api_writes.post.assert_not_awaited()
        mock_api_writes.get = AsyncMock(return_value={"account": {"enabled": "0"}})
        mock_api_writes.post = AsyncMock(return_value={"result": "ok"})
        result = await opn_set_ddns_account_enabled(mock_ctx_writes, "test-uuid", True)
        mock_api_writes.post.assert_awaited_once_with(
            "dyndns.accounts.toggle", path_suffix="test-uuid/1",
        )
        assert result["applied"] is False

    async def test_toggle_requires_writes_before_read(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_set_ddns_account_enabled(mock_ctx, "test-uuid", True)
        mock_api.get.assert_not_awaited()

    async def test_delete_stages_only(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        result = await opn_delete_ddns_account(mock_ctx_writes, "test-uuid")
        mock_api_writes.post.assert_awaited_once_with("dyndns.accounts.del", path_suffix="test-uuid")
        assert result["applied"] is False

    async def test_general_settings_whitelisted(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"ddclient": {"general": {
            "enabled": "1", "allowipv6": "1", "backend": "opnsense", "password": "bad",
        }}})
        result = await opn_get_ddns_settings(mock_ctx)
        assert result == {"general": {"enabled": "1", "allowipv6": "1", "backend": "opnsense"}}

    async def test_settings_patch_is_staged_and_validates(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        result = await opn_patch_ddns_settings(mock_ctx_writes, backend="opnsense", allowipv6=True)
        mock_api_writes.post.assert_awaited_once_with(
            "dyndns.settings.set", {"ddclient": {"general": {"allowipv6": "1", "backend": "opnsense"}}},
        )
        assert result["applied"] is False
        with pytest.raises(ValueError, match="backend"):
            await opn_patch_ddns_settings(mock_ctx_writes, backend="native")
        with pytest.raises(ValueError, match="daemon_delay"):
            await opn_patch_ddns_settings(mock_ctx_writes, daemon_delay=0)

    async def test_service_status_is_read_only(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running", "secret": "not-for-model"})
        assert await opn_ddns_service_status(mock_ctx) == {"status": "running"}
        mock_api.get.assert_awaited_once_with("dyndns.service.status")

    async def test_apply_requires_confirmation_and_write_permission(self, mock_api_writes, mock_ctx_writes, mock_ctx):
        with pytest.raises(ValueError, match="confirm"):
            await opn_reconfigure_ddclient(mock_ctx_writes)
        mock_api_writes.post.assert_not_awaited()
        with pytest.raises(WriteDisabledError):
            await opn_reconfigure_ddclient(mock_ctx, confirm=True)
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_ddclient(mock_ctx_writes, confirm=True)
        mock_api_writes.post.assert_awaited_once_with("dyndns.service.reconfigure")
        assert result["status"] == "ok"

    @pytest.mark.parametrize("action", ["start", "stop", "restart"])
    async def test_explicit_service_control(self, action, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        with pytest.raises(ValueError, match="confirm"):
            await opn_ddns_service_control(mock_ctx_writes, action=action)
        result = await opn_ddns_service_control(mock_ctx_writes, action=action, confirm=True)
        mock_api_writes.post.assert_awaited_once_with(f"dyndns.service.{action}")
        assert result == {"action": action, "status": "ok"}

    async def test_force_refresh_only_native_and_confirmed(self, mock_api_writes, mock_ctx_writes):
        with pytest.raises(ValueError, match="confirm"):
            await opn_force_refresh_ddns_accounts(mock_ctx_writes, "uuid-1")
        mock_api_writes.get = AsyncMock(return_value={
            "ddclient": {"general": {"enabled": "1", "backend": "ddclient"}},
        })
        with pytest.raises(ValueError, match="native"):
            await opn_force_refresh_ddns_accounts(mock_ctx_writes, "uuid-1", confirm=True)
        mock_api_writes.post.assert_not_awaited()
        mock_api_writes.get = AsyncMock(return_value={
            "ddclient": {"general": {"enabled": "1", "backend": "opnsense"}},
        })
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_force_refresh_ddns_accounts(mock_ctx_writes, "uuid-1", confirm=True)
        mock_api_writes.post.assert_awaited_once_with(
            "dyndns.accounts.force_refresh", path_suffix="uuid-1",
        )
        assert result["requested_accounts"] == 1


class TestOpnMdnsRepeaterStatus:
    """Tests for opn_mdns_repeater_status."""

    async def test_returns_status_and_config(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {
                    "mdnsrepeater": {
                        "enabled": "1",
                        "interfaces": "lan,opt1",
                        "blocklist": "",
                        "enablecarp": "0",
                    },
                },
                {"status": "running"},
            ],
        )
        result = await opn_mdns_repeater_status(mock_ctx)
        assert result["service_running"] == "running"
        assert result["enabled"] == "1"
        assert result["interfaces"] == "lan,opt1"
        assert result["blocklist"] == ""
        assert result["enable_carp"] == "0"

    async def test_disabled_service(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {
                    "mdnsrepeater": {
                        "enabled": "0",
                        "interfaces": "",
                        "blocklist": "",
                        "enablecarp": "0",
                    },
                },
                {"status": "stopped"},
            ],
        )
        result = await opn_mdns_repeater_status(mock_ctx)
        assert result["service_running"] == "stopped"
        assert result["enabled"] == "0"

    async def test_calls_correct_endpoints(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            side_effect=[
                {"mdnsrepeater": {"enabled": "0", "interfaces": ""}},
                {"status": "stopped"},
            ],
        )
        await opn_mdns_repeater_status(mock_ctx)
        calls = [c[0][0] for c in mock_api.get.call_args_list]
        assert calls == ["mdnsrepeater.settings.get", "mdnsrepeater.service.status"]


class TestOpnConfigureMdnsRepeater:
    """Tests for opn_configure_mdns_repeater."""

    async def test_requires_writes_enabled(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_configure_mdns_repeater(mock_ctx, interfaces="lan,opt1")

    async def test_configures_and_reconfigures(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved"},
                {"status": "ok"},
            ],
        )
        result = await opn_configure_mdns_repeater(mock_ctx_writes, enabled=True, interfaces="lan,opt1")
        # First call: set settings
        set_call = mock_api_writes.post.call_args_list[0]
        assert set_call[0][0] == "mdnsrepeater.settings.set"
        payload = set_call[0][1]
        assert payload["mdnsrepeater"]["enabled"] == "1"
        assert payload["mdnsrepeater"]["interfaces"] == "lan,opt1"
        # Second call: reconfigure
        reconf_call = mock_api_writes.post.call_args_list[1]
        assert reconf_call[0][0] == "mdnsrepeater.service.reconfigure"
        # Result
        assert result["result"] == "saved"
        assert result["reconfigure_status"] == "ok"
        assert result["interfaces"] == "lan,opt1"

    async def test_disable_mdns_repeater(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(
            side_effect=[
                {"result": "saved"},
                {"status": "ok"},
            ],
        )
        result = await opn_configure_mdns_repeater(mock_ctx_writes, enabled=False, interfaces="lan")
        set_call = mock_api_writes.post.call_args_list[0]
        payload = set_call[0][1]
        assert payload["mdnsrepeater"]["enabled"] == "0"
        assert result["enabled"] == "0"


