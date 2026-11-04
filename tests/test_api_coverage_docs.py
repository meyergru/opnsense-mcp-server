"""Ensure the published API-coverage docs do not silently lag behind MCP tools.

These assertions protect inventory snapshots. They do *not* imply every
upstream OPNsense controller/action is implemented.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from opnsense_mcp.api_client import ENDPOINT_REGISTRY, WRITE_OPERATIONS
from opnsense_mcp.mvc_catalog import MVC_ENDPOINTS


@pytest.mark.asyncio
async def test_api_coverage_documentation_matches_registered_tools():
    from opnsense_mcp.server import mcp

    base = Path(__file__).resolve().parents[1]
    readme = (base / "README.md").read_text(encoding="utf-8")
    coverage = (base / "docs" / "core-api-coverage-26.7.md").read_text(encoding="utf-8")
    policy = (base / "docs" / "api-operation-policy.md").read_text(encoding="utf-8")
    count = len(await mcp.list_tools())

    # Counts in all human-facing overview documents must move together.
    assert f"**{count} tools" in readme
    assert f"## Available Tools ({count})" in readme
    assert f"**{count} tools**" in coverage
    assert f"**{count} MCP tools**" in policy

    # The matrix must report current families and the known Firewall gaps.
    for heading in ("Kea", "Radvd", "Unbound", "Wireguard", "Firewall"):
        assert re.search(r"^\\| " + heading + r" \\|", coverage, re.MULTILINE)
    for missing_controller in ("SourceNat", "OneToOne", "Npt", "AliasUtil"):
        assert f"`{missing_controller}`" in coverage

    # Every generated resource operation is still protected by the
    # authoritative client registry and classified operations.
    assert MVC_ENDPOINTS.keys() <= ENDPOINT_REGISTRY.keys()
    assert ("POST", "mvc.wireguard.peer.del") in WRITE_OPERATIONS
    assert ("POST", "mvc.wireguard.peer.toggle") in WRITE_OPERATIONS
