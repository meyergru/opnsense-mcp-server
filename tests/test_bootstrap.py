"""Startup validation and Docker restart-loop regression tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from opnsense_mcp.bootstrap import main, validate_startup_configuration
from opnsense_mcp.config import ConfigError


def _http_env() -> dict[str, str]:
    return {
        "OPNSENSE_MCP_TRANSPORT": "http",
        "OPNSENSE_MCP_HOST": "0.0.0.0",
        "OPNSENSE_MCP_AUTH_TOKEN": "a" * 64,
        "OPNSENSE_SITES": "opnsense.mgsoft",
        "OPNSENSE_OPNSENSE_MGSOFT_URL": "https://192.0.2.1/api",
        "OPNSENSE_OPNSENSE_MGSOFT_API_KEY": "test-key",
        "OPNSENSE_OPNSENSE_MGSOFT_API_SECRET": "TOP_SECRET_NOT_TO_LOG",
        "OPNSENSE_MCP_CONFIG_ERROR_HOLD": "true",
    }


def test_valid_configuration_preflights_without_live_firewall():
    with patch.dict("os.environ", _http_env(), clear=True):
        validate_startup_configuration()


def test_typo_suggests_actual_variable_name_without_credentials():
    env = _http_env()
    env["OPNSENSE_OPNSENSE_MGSOFT_AP_SECRET"] = env.pop(
        "OPNSENSE_OPNSENSE_MGSOFT_API_SECRET"
    )
    with patch.dict("os.environ", env, clear=True):
        with pytest.raises(ConfigError) as error:
            validate_startup_configuration()
    message = str(error.value)
    assert "OPNSENSE_OPNSENSE_MGSOFT_API_SECRET" in message
    assert "OPNSENSE_OPNSENSE_MGSOFT_AP_SECRET" in message
    assert "TOP_SECRET_NOT_TO_LOG" not in message


def test_invalid_config_in_portainer_holds_without_traceback(capsys):
    env = _http_env()
    env.pop("OPNSENSE_OPNSENSE_MGSOFT_API_KEY")
    with (
        patch.dict("os.environ", env, clear=True),
        patch("opnsense_mcp.bootstrap.time.sleep", side_effect=KeyboardInterrupt) as sleeping,
    ):
        with pytest.raises(KeyboardInterrupt):
            main()
    stderr = capsys.readouterr().err
    assert "CONFIGURATION ERROR" in stderr
    assert "OPNSENSE_OPNSENSE_MGSOFT_API_KEY" in stderr
    assert "Traceback" not in stderr
    assert "TOP_SECRET_NOT_TO_LOG" not in stderr
    assert "unhealthy" in stderr
    sleeping.assert_called_once_with(3600)


def test_invalid_stdio_config_exits_with_code_2_and_no_traceback(capsys):
    with patch.dict("os.environ", {"OPNSENSE_MCP_TRANSPORT": "stdio"}, clear=True):
        with pytest.raises(SystemExit) as error:
            main()
    assert error.value.code == 2
    stderr = capsys.readouterr().err
    assert "CONFIGURATION ERROR" in stderr
    assert "OPNSENSE_URL" in stderr
    assert "Traceback" not in stderr


def test_invalid_transport_is_explained_without_traceback(capsys):
    env = {"OPNSENSE_MCP_TRANSPORT": "wrong-mode", "OPNSENSE_MCP_CONFIG_ERROR_HOLD": "true"}
    with (
        patch.dict("os.environ", env, clear=True),
        patch("opnsense_mcp.bootstrap.time.sleep", side_effect=KeyboardInterrupt),
    ):
        with pytest.raises(KeyboardInterrupt):
            main()
    stderr = capsys.readouterr().err
    assert "OPNSENSE_MCP_TRANSPORT" in stderr
    assert "Traceback" not in stderr


def test_valid_configuration_starts_original_server():
    with (
        patch.dict("os.environ", _http_env(), clear=True),
        patch("opnsense_mcp.server.main") as server_main,
    ):
        main()
    server_main.assert_called_once_with()
