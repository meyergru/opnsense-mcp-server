"""Audit every OPNsense endpoint and actual API callsite against explicit policy.

The runtime fails closed. These checks additionally ensure changes to the
registry and tools require a code-reviewable classification before CI passes.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from opnsense_mcp.api_client import (
    DIAGNOSTIC_OPERATIONS,
    ENDPOINT_REGISTRY,
    READ_ONLY_GET_ENDPOINTS,
    READ_ONLY_POST_ENDPOINTS,
    WRITE_OPERATIONS,
    OperationEffect,
    WriteDisabledError,
    operation_effect,
)

_SOURCE = Path(__file__).resolve().parents[1] / "src" / "opnsense_mcp"


def _catalog() -> set[tuple[str, str]]:
    """All fully approved API operations, including dynamically registered HAProxy."""
    return (
        {("GET", x) for x in READ_ONLY_GET_ENDPOINTS}
        | {("POST", x) for x in READ_ONLY_POST_ENDPOINTS}
        | DIAGNOSTIC_OPERATIONS
        | WRITE_OPERATIONS
    )


def test_every_static_registry_entry_has_a_reviewed_operation():
    approved = {endpoint for _, endpoint in _catalog()}
    assert ENDPOINT_REGISTRY.keys() <= approved


def test_all_operation_classes_are_disjoint():
    groups = [
        {("GET", x) for x in READ_ONLY_GET_ENDPOINTS},
        {("POST", x) for x in READ_ONLY_POST_ENDPOINTS},
        DIAGNOSTIC_OPERATIONS,
        WRITE_OPERATIONS,
    ]
    for idx, group in enumerate(groups):
        for other in groups[idx + 1 :]:
            assert group.isdisjoint(other)


def test_dynamic_haproxy_crud_operations_are_explicitly_reviewed():
    resources = (
        "frontend",
        "backend",
        "server",
        "action",
        "acl",
        "healthcheck",
        "errorfile",
        "resolver",
        "mailer",
    )
    for name in resources:
        endpoint = f"haproxy.settings.get_{name}"
        assert ("GET", endpoint) in _catalog()
        assert operation_effect("GET", endpoint) is OperationEffect.READ
        for verb in ("add", "set", "del"):
            endpoint = f"haproxy.settings.{verb}_{name}"
            assert ("POST", endpoint) in WRITE_OPERATIONS
            assert operation_effect("POST", endpoint) is OperationEffect.WRITE


def test_tool_api_calls_are_all_explicitly_classified():
    """Prevent any tool from silently calling a new endpoint via GET or POST."""
    approved = _catalog()
    dynamic_calls = {
        ("haproxy.py", "get", "logical"),
        ("haproxy.py", "post", "logical"),
        ("haproxy.py", "post", "endpoint"),
        ("security.py", "post", "endpoint"),
    }
    for source_path in _SOURCE.rglob("*.py"):
        if source_path.name == "api_client.py":
            continue
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            method = node.func.attr
            if method not in {"get", "post", "get_text"}:
                continue
            if not isinstance(node.func.value, ast.Name) or node.func.value.id != "api":
                continue
            if not node.args:
                pytest.fail(f"{source_path.name}:{node.lineno} missing API endpoint argument")
            argument = node.args[0]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                key = ("GET" if method in {"get", "get_text"} else "POST", argument.value)
                assert key in approved, f"{source_path.name}:{node.lineno}: unreviewed API call {key}"
            elif isinstance(argument, ast.Name):
                dynamic = (source_path.name, method, argument.id)
                assert dynamic in dynamic_calls, (
                    f"{source_path.name}:{node.lineno}: unreviewed dynamic API call {dynamic}"
                )
            else:
                pytest.fail(f"{source_path.name}:{node.lineno}: unexpected dynamic API expression")


def test_all_known_write_endpoints_are_classified_as_writes():
    for method, endpoint in WRITE_OPERATIONS:
        assert operation_effect(method, endpoint) is OperationEffect.WRITE


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["get", "post"])
async def test_unreviewed_operation_is_denied_even_on_writable_site(mock_api_writes, method):
    ENDPOINT_REGISTRY["_unreviewed_test"] = ("test/new_endpoint", "test/new_endpoint")
    try:
        with pytest.raises(WriteDisabledError, match="Unclassified"):
            await getattr(mock_api_writes, method)("_unreviewed_test")
        mock_api_writes._client.get.assert_not_awaited()
        mock_api_writes._client.post.assert_not_awaited()
    finally:
        ENDPOINT_REGISTRY.pop("_unreviewed_test")


@pytest.mark.asyncio
async def test_known_write_operation_still_requires_writable_site(mock_api_writes):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"result": "ok"}
    mock_api_writes._client.post.return_value = response
    result = await mock_api_writes.post("firewall.add_rule", {"rule": {"description": "test"}})
    assert result == {"result": "ok"}
    mock_api_writes._client.post.assert_awaited_once()
