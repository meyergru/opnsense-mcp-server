"""Tests for native Compose/environment-only multi-target configuration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opnsense_mcp.config import ConfigError
from opnsense_mcp.targets import TargetError, TargetRegistry


def _env() -> dict[str, str]:
    return {
        "OPNSENSE_SITES": "alpha,beta",
        "OPNSENSE_ALPHA_URL": "https://10.0.0.1/api",
        "OPNSENSE_ALPHA_API_KEY": "alpha-key",
        "OPNSENSE_ALPHA_API_SECRET": "alpha-secret",
        "OPNSENSE_BETA_URL": "https://192.168.20.1:10443/api",
        "OPNSENSE_BETA_API_KEY": "beta-key",
        "OPNSENSE_BETA_API_SECRET": "beta-secret",
        "OPNSENSE_BETA_VERIFY_SSL": "false",
    }


@pytest.mark.asyncio
async def test_independent_clients_and_caches():
    with patch.dict("os.environ", _env(), clear=True):
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
        assert alpha.api._config.verify_ssl is True
        assert beta.api._config.verify_ssl is False
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
    with patch.dict("os.environ", {"OPNSENSE_SITES": ""}):
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
def test_reject_invalid_url(url):
    env = _env()
    env["OPNSENSE_ALPHA_URL"] = url
    with patch.dict("os.environ", env, clear=True), pytest.raises(ConfigError):
        TargetRegistry.from_environment()


def test_reject_missing_credentials():
    env = _env()
    env.pop("OPNSENSE_ALPHA_API_SECRET")
    with patch.dict("os.environ", env, clear=True):
        with pytest.raises(ConfigError, match="OPNSENSE_ALPHA_API_SECRET"):
            TargetRegistry.from_environment()


@pytest.mark.parametrize("sites", ["alpha,alpha", "alpha,,beta", "alpha,site-two", "Alpha"])
def test_reject_invalid_site_inventory(sites):
    env = _env()
    env["OPNSENSE_SITES"] = sites
    with patch.dict("os.environ", env, clear=True), pytest.raises(ConfigError):
        TargetRegistry.from_environment()


def test_reject_invalid_tls_setting():
    env = _env()
    env["OPNSENSE_ALPHA_VERIFY_SSL"] = "maybe"
    with patch.dict("os.environ", env, clear=True), pytest.raises(ConfigError, match="VERIFY_SSL"):
        TargetRegistry.from_environment()


@pytest.mark.asyncio
async def test_single_named_site_can_be_implicit():
    env = {key: value for key, value in _env().items() if "BETA" not in key}
    env["OPNSENSE_SITES"] = "alpha"
    with patch.dict("os.environ", env, clear=True):
        registry = TargetRegistry.from_environment()
    try:
        assert registry.resolve() is registry.resolve("alpha")
    finally:
        await registry.close()


@pytest.mark.asyncio
async def test_helpers_route_to_same_site_state():
    """API, cache and savepoint accessors cannot cross sites."""
    from opnsense_mcp.server import get_api, get_config_cache, get_savepoint_manager

    with patch.dict("os.environ", _env(), clear=True):
        registry = TargetRegistry.from_environment()

    try:
        ctx = MagicMock()
        ctx.lifespan_context = {"targets": registry}
        assert get_api(ctx, "alpha") is registry.resolve("alpha").api
        assert get_api(ctx, "beta") is registry.resolve("beta").api
        assert get_config_cache(ctx, "alpha") is registry.resolve("alpha").config_cache
        assert get_savepoint_manager(ctx, "beta") is registry.resolve("beta").savepoint_mgr
        with pytest.raises(TargetError, match="site is required"):
            get_api(ctx)
    finally:
        await registry.close()
