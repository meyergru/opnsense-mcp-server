"""Tests for the remote HTTP transport configuration (no live ports used)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from opnsense_mcp.transport import build_auth, load_transport_config


def test_stdio_default():
    with patch.dict("os.environ", {}, clear=True):
        settings = load_transport_config()
    assert settings.transport == "stdio"
    assert build_auth(settings) is None


def test_http_requires_bearer_token():
    with patch.dict("os.environ", {"OPNSENSE_MCP_TRANSPORT": "http"}, clear=True):
        with pytest.raises(ValueError, match="AUTH_TOKEN"):
            load_transport_config()


@pytest.mark.parametrize(
    "token",
    ["", "short", "a" * 31, "a" * 257, "a" * 32 + " ", "a" * 16 + "\n" + "b" * 16],
)
def test_http_rejects_invalid_tokens(token):
    with patch.dict(
        "os.environ",
        {"OPNSENSE_MCP_TRANSPORT": "http", "OPNSENSE_MCP_AUTH_TOKEN": token},
        clear=True,
    ):
        with pytest.raises(ValueError, match="AUTH_TOKEN"):
            load_transport_config()


def test_http_requires_valid_host_and_port():
    env = {"OPNSENSE_MCP_TRANSPORT": "http", "OPNSENSE_MCP_AUTH_TOKEN": "a" * 64}
    for key, value in (
        ("OPNSENSE_MCP_PORT", "0"),
        ("OPNSENSE_MCP_PORT", "65536"),
        ("OPNSENSE_MCP_PORT", "invalid"),
        ("OPNSENSE_MCP_HOST", ""),
    ):
        with patch.dict("os.environ", {**env, key: value}, clear=True):
            with pytest.raises(ValueError):
                load_transport_config()


def test_http_config_and_verifier():
    env = {
        "OPNSENSE_MCP_TRANSPORT": "http",
        "OPNSENSE_MCP_AUTH_TOKEN": "a" * 64,
        "OPNSENSE_MCP_HOST": "127.0.0.1",
        "OPNSENSE_MCP_PORT": "8123",
    }
    with patch.dict("os.environ", env, clear=True):
        settings = load_transport_config()
    assert settings.host == "127.0.0.1"
    assert settings.port == 8123
    assert "a" * 64 not in repr(settings)
    assert build_auth(settings) is not None


@pytest.mark.parametrize("transport", ["sse", "nonsense", "streamable-http"])
def test_reject_unexpected_transport(transport):
    with patch.dict("os.environ", {"OPNSENSE_MCP_TRANSPORT": transport}, clear=True):
        with pytest.raises(ValueError, match="TRANSPORT"):
            load_transport_config()
