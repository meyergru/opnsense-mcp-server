"""Guard documentation inventory counts against silent API/Tool growth.

Controller action completeness still requires review of OPNsense source.
"""

from __future__ import annotations

from pathlib import Path

from opnsense_mcp.api_client import ENDPOINT_REGISTRY
from opnsense_mcp.firewall_catalog import FIREWALL_ENDPOINTS
from opnsense_mcp.mvc_catalog import MVC_ENDPOINTS

_ROOT = Path(__file__).resolve().parents[1]


def test_documented_api_catalog_counts_match_runtime():
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    policy = (_ROOT / "docs" / "api-operation-policy.md").read_text(encoding="utf-8")
    coverage = (_ROOT / "docs" / "core-api-coverage-26.7.md").read_text(encoding="utf-8")

    base_count = len(ENDPOINT_REGISTRY) - len(MVC_ENDPOINTS) - len(FIREWALL_ENDPOINTS)
    assert f"**{len(ENDPOINT_REGISTRY)}** registered logical endpoints" in policy
    assert f"{base_count} original/static mappings" in policy
    assert f"{len(MVC_ENDPOINTS)} generated reviewed MVC mappings" in policy
    assert f"{len(FIREWALL_ENDPOINTS)} generated reviewed Firewall 26.7 mappings" in policy
    assert f"{len(FIREWALL_ENDPOINTS)} additional reviewed logical endpoints" in coverage
    assert "**149 MCP tools:**" in readme
    assert "**149 MCP tools**" in policy


async def test_documented_tool_count_matches_actual_runtime():
    from opnsense_mcp.server import mcp

    count = len(await mcp.list_tools())
    assert count == 149
    assert f"**{count} MCP tools:**" in (_ROOT / "README.md").read_text(encoding="utf-8")
