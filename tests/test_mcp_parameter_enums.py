"""MCP input choice types must match the implementation's audited domains.

This prevents agents having to guess OPNsense-internal spelling or valid
enumerated choices, and prevents advertised enums drifting from validators.
"""

from __future__ import annotations

from typing import get_args, get_type_hints

import pytest

from opnsense_mcp.firewall_catalog import (
    RESOURCES as FIREWALL_RESOURCES,
)
from opnsense_mcp.firewall_catalog import (
    FirewallLoggingKind,
    FirewallMoveKind,
    FirewallResourceName,
    FirewallToggleKind,
)
from opnsense_mcp.mvc_catalog import (
    APPLY_SERVICES,
    GLOBAL_SETTINGS,
    RESOURCES,
    ApplyServiceName,
    SettingsSubsystemName,
    UnboundResourceName,
)
from opnsense_mcp.tools import diagnostics, firewall, firewall_mvc, haproxy, mvc


def test_mvc_resource_enums_match_catalogue():
    assert set(get_args(UnboundResourceName)) == set(RESOURCES["unbound"])
    assert set(get_args(SettingsSubsystemName)) == set(GLOBAL_SETTINGS)
    assert set(get_args(ApplyServiceName)) == set(APPLY_SERVICES)


def test_firewall_resource_enums_match_capabilities():
    assert set(get_args(FirewallResourceName)) == set(FIREWALL_RESOURCES)
    assert set(get_args(FirewallToggleKind)) == {k for k, v in FIREWALL_RESOURCES.items() if v.toggle}
    assert set(get_args(FirewallLoggingKind)) == {k for k, v in FIREWALL_RESOURCES.items() if v.logging}
    assert set(get_args(FirewallMoveKind)) == {k for k, v in FIREWALL_RESOURCES.items() if v.movable}


@pytest.mark.parametrize(
    ("tool", "parameter", "values"),
    [
        *[(getattr(mvc, n), "resource", get_args(UnboundResourceName))
          for n in ("opn_unbound_list", "opn_unbound_get", "opn_unbound_add",
                    "opn_unbound_patch", "opn_unbound_delete", "opn_unbound_toggle")],
        *[(getattr(mvc, n), "subsystem", get_args(SettingsSubsystemName))
          for n in ("opn_mvc_get_settings", "opn_mvc_patch_settings")],
        (mvc.opn_service_apply, "service", get_args(ApplyServiceName)),
        *[(getattr(firewall_mvc, n), "kind", get_args(FirewallResourceName))
          for n in ("opn_firewall_list_objects", "opn_firewall_get_object",
                    "opn_firewall_create_object", "opn_firewall_patch_object",
                    "opn_firewall_delete_object")],
        (firewall_mvc.opn_firewall_set_enabled, "kind", get_args(FirewallToggleKind)),
        (firewall_mvc.opn_firewall_set_logging, "kind", get_args(FirewallLoggingKind)),
        (firewall_mvc.opn_firewall_move_rule, "kind", get_args(FirewallMoveKind)),
        *[(getattr(haproxy, n), "resource_type", get_args(haproxy.HAProxyResourceType))
          for n in ("opn_haproxy_search", "opn_haproxy_get", "opn_haproxy_add",
                    "opn_haproxy_update", "opn_haproxy_delete")],
        (diagnostics.opn_traceroute, "protocol", ("ICMP", "UDP", "TCP")),
        (diagnostics.opn_traceroute, "ip_version", ("4", "6")),
    ],
)
def test_registered_choices_are_explicit_in_tool_annotations(tool, parameter, values):
    assert set(get_args(get_type_hints(tool)[parameter])) == set(values)


def test_firewall_simple_enum_aliases_track_input_validation():
    assert set(get_args(firewall.FirewallAction)) == set(firewall._VALID_ACTIONS)
    assert set(get_args(firewall.FirewallDirection)) == set(firewall._VALID_DIRECTIONS)
    assert set(get_args(firewall.FirewallIPProtocol)) == set(firewall._VALID_IP_PROTOCOLS)
    assert set(get_args(firewall.FirewallAliasType)) == set(firewall._VALID_ALIAS_TYPES)
    assert set(get_args(firewall.FirewallNATProtocol)) == set(firewall._VALID_NAT_PROTOCOLS)


@pytest.mark.parametrize(
    ("tool", "parameter", "values"),
    [
        (firewall.opn_add_firewall_rule, "action", get_args(firewall.FirewallAction)),
        (firewall.opn_add_firewall_rule, "direction", get_args(firewall.FirewallDirection)),
        (firewall.opn_add_firewall_rule, "ip_protocol", get_args(firewall.FirewallIPProtocol)),
        (firewall.opn_add_alias, "alias_type", get_args(firewall.FirewallAliasType)),
        (firewall.opn_add_nat_rule, "protocol", get_args(firewall.FirewallNATProtocol)),
    ],
)
def test_add_operations_advertise_valid_firewall_enums(tool, parameter, values):
    assert set(get_args(get_type_hints(tool)[parameter])) == set(values)
