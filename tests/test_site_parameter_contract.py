"""Every site-targeted MCP tool must explain how to find valid site names."""

from __future__ import annotations

import importlib
import inspect
from typing import get_type_hints

from pydantic import TypeAdapter

MODULES = (
    "dhcp",
    "diagnostics",
    "dns",
    "firewall",
    "firewall_mvc",
    "firmware",
    "firmware_cve",
    "haproxy",
    "mvc",
    "network",
    "security",
    "services",
    "snapshots",
    "system",
    "vpn",
)


def test_every_site_targeted_tool_describes_the_dynamic_site_parameter():
    total = 0
    for name in MODULES:
        module = importlib.import_module(f"opnsense_mcp.tools.{name}")
        for member_name, function in vars(module).items():
            if not member_name.startswith("opn_") or not inspect.iscoroutinefunction(function):
                continue
            total += 1
            assert "site" in inspect.signature(function).parameters, member_name
            site_type = get_type_hints(function, include_extras=True)["site"]
            schema = TypeAdapter(site_type).json_schema()
            assert schema["type"] == "string", member_name
            assert "opn_list_targets" in schema["description"], member_name
    assert total >= 140
