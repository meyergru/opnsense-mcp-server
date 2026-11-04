"""MCP structured results require an object at the top level."""

from __future__ import annotations

import pytest

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.tool_result import structured_table_result


def test_object_response_preserved_unchanged():
    payload = {"rows": [{"address": "192.0.2.1"}], "total": 1, "current": 1}
    assert structured_table_result(payload) is payload


def test_array_response_wrapped_without_losing_rows():
    row = {"ip": "192.0.2.1", "mac": "00:11:22:33:44:55"}
    assert structured_table_result([row]) == {"rows": [row], "rowCount": 1}


def test_empty_array_is_successful_empty_table():
    assert structured_table_result([]) == {"rows": [], "rowCount": 0}


@pytest.mark.parametrize("value", [None, "bad response", 123, True])
def test_invalid_response_type_rejected(value):
    with pytest.raises(OPNsenseAPIError, match="Unexpected table response type"):
        structured_table_result(value)
