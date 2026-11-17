"""Regression test: all exposed MCP parameters are described and correctly required.

The server exposes approximately 150 OPNsense operations. Human-friendly
docstrings alone are insufficient: the *generated MCP JSON Schema* is what
the agent actually sees. Test that exact contract for every operation.
"""

from __future__ import annotations

import importlib
import inspect

from opnsense_mcp.server import mcp

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


async def test_every_tool_parameter_is_described_and_requiredness_matches_python_signature() -> None:
    registered = {tool.name: tool for tool in await mcp.list_tools()}
    assert len(registered) == 151, "Review all newly added or removed tools"

    targets = registered["opn_list_targets"]
    assert not targets.parameters.get("properties", {})
    assert not targets.parameters.get("required", [])

    checked: set[str] = set()
    for name in MODULES:
        module = importlib.import_module(f"opnsense_mcp.tools.{name}")
        for member_name, func in vars(module).items():
            if (
                not member_name.startswith("opn_")
                or not inspect.iscoroutinefunction(func)
                or func.__module__ != module.__name__
            ):
                continue
            assert member_name in registered, f"Unregistered tool {member_name}"
            assert member_name not in checked, f"Duplicate tool {member_name}"
            checked.add(member_name)
            signature = inspect.signature(func)
            expected = {param.name for param in signature.parameters.values() if param.name != "ctx"}
            required = {
                param.name
                for param in signature.parameters.values()
                if param.name != "ctx" and param.default is inspect.Parameter.empty
            }
            schema = registered[member_name].parameters
            properties = schema["properties"]
            assert set(properties) == expected, f"{member_name}: mismatched MCP schema inputs"
            assert set(schema.get("required", [])) == required, f"{member_name}: incorrect required parameters"
            for param_name, prop in properties.items():
                description = prop.get("description", "")
                assert isinstance(description, str) and description.strip(), (
                    f"{member_name}.{param_name}: MCP schema has no parameter description"
                )
            assert "opn_list_targets" in properties["site"]["description"], member_name

    assert checked == set(registered) - {"opn_list_targets"}


async def test_mcp_info_has_mandatory_nonempty_site_in_actual_mcp_schema() -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    info_schema = tools["opn_mcp_info"].parameters
    assert "site" in info_schema["required"]
    assert info_schema["properties"]["site"]["minLength"] == 1
    assert "opn_list_targets" in info_schema["properties"]["site"]["description"]
