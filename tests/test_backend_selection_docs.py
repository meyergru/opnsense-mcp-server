"""Prevent service-specific tools from presenting inactive configs as live state."""

from __future__ import annotations

import importlib
import inspect

import pytest

BACKEND_TOOLS = {
    "dhcp": (
        "opn_list_dhcp_leases",
        "opn_list_kea_leases",
        "opn_list_dnsmasq_leases",
        "opn_list_dnsmasq_ranges",
        "opn_add_dnsmasq_range",
        "opn_update_dnsmasq_range",
        "opn_delete_dnsmasq_range",
        "opn_reconfigure_dnsmasq",
    ),
    "mvc": (
        "opn_kea_list",
        "opn_kea_get",
        "opn_kea_add",
        "opn_kea_patch",
        "opn_kea_delete",
        "opn_kea_list_leases6",
        "opn_kea_delete_lease",
        "opn_radvd_list",
        "opn_radvd_get",
        "opn_radvd_add",
        "opn_radvd_patch",
        "opn_radvd_delete",
        "opn_radvd_toggle",
        "opn_mvc_get_settings",
        "opn_mvc_patch_settings",
        "opn_service_apply",
    ),
    "haproxy": (
        "opn_haproxy_status",
        "opn_haproxy_search",
        "opn_haproxy_get",
        "opn_haproxy_add",
        "opn_haproxy_update",
        "opn_haproxy_delete",
        "opn_haproxy_configtest",
        "opn_reconfigure_haproxy",
    ),
    "dns": (
        "opn_list_dns_overrides",
        "opn_list_dns_forwards",
        "opn_dns_stats",
        "opn_reconfigure_unbound",
        "opn_add_dns_override",
        "opn_update_dns_override",
        "opn_delete_dns_override",
        "opn_list_dnsbl",
        "opn_get_dnsbl",
        "opn_set_dnsbl",
        "opn_add_dnsbl_allowlist",
        "opn_remove_dnsbl_allowlist",
        "opn_update_dnsbl",
    ),
    "system": ("opn_scan_config", "opn_list_services"),
    "vpn": ("opn_wireguard_status", "opn_ipsec_status", "opn_openvpn_status"),
    "diagnostics": ("opn_dns_lookup",),
}


@pytest.mark.parametrize(
    ("module_name", "function_name"),
    [
        (module_name, name)
        for module_name, names in BACKEND_TOOLS.items()
        for name in names
    ],
)
def test_service_specific_tools_warn_about_inactive_alternatives(module_name, function_name):
    module = importlib.import_module(f"opnsense_mcp.tools.{module_name}")
    func = getattr(module, function_name)
    doc = inspect.getdoc(func)
    assert doc is not None, function_name
    assert "BACKEND SELECTION:" in doc, function_name


def test_backend_selection_guidance_covers_distinct_service_roles():
    from opnsense_mcp.tools import dhcp, haproxy, mvc, system

    assert "stale" in inspect.getdoc(dhcp.opn_list_kea_leases).lower()
    assert "different interfaces" in inspect.getdoc(system.opn_scan_config).lower()
    assert "dnsmasq" in inspect.getdoc(mvc.opn_radvd_list).lower()
    assert "radvd" in inspect.getdoc(dhcp.opn_list_dnsmasq_ranges).lower()
    assert "Nginx" in inspect.getdoc(haproxy.opn_haproxy_search)
    assert "Caddy" in inspect.getdoc(haproxy.opn_haproxy_search)
    assert "chained" in inspect.getdoc(haproxy.opn_haproxy_search)
