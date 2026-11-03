"""Tests for native multi-target configuration and isolation."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from opnsense_mcp.config import ConfigError
from opnsense_mcp.targets import TargetError, TargetRegistry


def _inventory() -> str:
    return """
[targets.alpha]
url = "https://10.0.0.1/api"
api_key_env = "API_KEY_ALPHA"
api_secret_env = "API_SECRET_ALPHA"

[targets.beta]
url = "https://192.168.20.1:10443/api"
api_key_env = "API_KEY_BETA"
api_secret_env = "API_SECRET_BETA"
"""


@pytest.mark.asyncio
async def test_independent_clients_and_caches(tmp_path):
    path = tmp_path / "targets.toml"
    path.write_text(_inventory())
    env = {
        "OPNSENSE_TARGETS_FILE": str(path),
        "API_KEY_ALPHA": "alpha-key",
        "API_SECRET_ALPHA": "alpha-secret",
        "API_KEY_BETA": "beta-key",
        "API_SECRET_BETA": "beta-secret",
    }
    with patch.dict("os.environ", env, clear=True):
        registry = TargetRegistry.from_environment()
    try:
        assert registry.names == ["alpha", "beta"]
        alpha = registry.resolve("alpha")
        beta = registry.resolve("beta")
        assert alpha.api is not beta.api
        assert alpha.config_cache is not beta.config_cache
        assert alpha.savepoint_mgr is not beta.savepoint_mgr
        assert alpha.api._config.url == "https://10.0.0.1/api"
        assert beta.api._config.url == "https://192.168.20.1:10443/api"
        assert alpha.api._config.allow_writes is False
        assert beta.api._config.allow_writes is False
        assert "alpha-secret" not in repr(alpha.api._config)
        with pytest.raises(TargetError, match="site is required"):
            registry.resolve()
        with pytest.raises(TargetError, match="Unknown OPNsense site"):
            registry.resolve("unknown")
    finally:
        await registry.close()


@pytest.mark.asyncio
async def test_legacy_single_target(env_vars):
    with patch.dict("os.environ", {"OPNSENSE_TARGETS_FILE": ""}):
        registry = TargetRegistry.from_environment()
    try:
        assert registry.names == ["default"]
        assert registry.resolve() is registry.resolve("default")
    finally:
        await registry.close()


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.1/api",
        "https://evil.example/api?token=1",
        "https://user:pass@10.0.0.1/api",
        "https://10.0.0.1/admin",
        "https://10.0.0.1:99999/api",
    ],
)
def test_reject_invalid_url(tmp_path, url):
    path = tmp_path / "targets.toml"
    path.write_text(_inventory().replace("https://10.0.0.1/api", url))
    env = {
        "OPNSENSE_TARGETS_FILE": str(path),
        "API_KEY_ALPHA": "alpha-key",
        "API_SECRET_ALPHA": "alpha-secret",
        "API_KEY_BETA": "beta-key",
        "API_SECRET_BETA": "beta-secret",
    }
    with patch.dict("os.environ", env, clear=True), pytest.raises(ConfigError):
        TargetRegistry.from_environment()


def test_reject_missing_credentials(tmp_path):
    path = tmp_path / "targets.toml"
    path.write_text(_inventory())
    with patch.dict("os.environ", {"OPNSENSE_TARGETS_FILE": str(path)}, clear=True):
        with pytest.raises(ConfigError, match="Missing credentials"):
            TargetRegistry.from_environment()
