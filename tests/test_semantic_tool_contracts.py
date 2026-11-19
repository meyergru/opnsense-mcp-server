"""Semantic MCP consumer contracts: verify input provenance in exposed help."""

from opnsense_mcp.server import mcp


async def test_tools_expose_return_field_lineage_and_workflow_boundaries():
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert len(tools) == 151

    def description(name: str) -> str:
        return tools[name].description

    assert "sites[]" in description("opn_list_targets")
    assert "rows[].uuid" in description("opn_kea_list")
    assert "rows[].uuid" in description("opn_unbound_list")
    assert "rows[].uuid" in description("opn_firewall_list_objects")
    assert "legacy" in description("opn_firewall_list_objects")
    assert "opn_list_snapshots" in description("opn_get_snapshot")
    assert "NOT a full Proxmox QEMU" in description("opn_create_snapshot")
    assert "psk_ref" in description("opn_wireguard_generate_psk")
    assert 'status="ready"' in description("opn_firmware_update_running")
    assert 'status="ready"' in description("opn_start_firmware_update")
    assert 'status="ready"' in description("opn_start_firmware_upgrade")
    assert "none (no updates)" in description("opn_check_firmware_updates")

    schema = tools["opn_kea_list"].parameters["properties"]
    assert "opn_list_targets" in schema["site"]["description"]
    assert set(schema["resource"]["enum"]) == {
        "subnet4", "reservation4", "option4", "ha_peer4",
        "subnet6", "reservation6", "option6", "pd_pool6", "ha_peer6",
    }
