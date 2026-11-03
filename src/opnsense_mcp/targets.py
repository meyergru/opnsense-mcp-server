"""Named OPNsense targets with independent API connections and configuration caches.

Set OPNSENSE_TARGETS_FILE to a local TOML file for multi-target operation.
Without it, the original single-target environment variables still work.
The site name is a lookup key, never a URL supplied by an MCP tool caller.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config import ConfigError, OPNsenseConfig, load_config
from opnsense_mcp.config_cache import ConfigCache

_SITE_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_ENV_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ALLOWED_FIELDS = frozenset({"url", "api_key_env", "api_secret_env", "verify_ssl"})


class TargetError(ValueError):
    """Unknown target or ambiguous target selection."""


@dataclass
class TargetState:
    """Independent state for one firewall."""

    api: OPNsenseAPI
    savepoint_mgr: SavepointManager
    config_cache: ConfigCache


class TargetRegistry:
    """Immutable mapping from site names to independent firewall clients."""

    def __init__(self, configs: dict[str, OPNsenseConfig]) -> None:
        if not configs:
            raise ConfigError("At least one OPNsense target is required")
        self._targets: dict[str, TargetState] = {}
        for name, config in configs.items():
            if not _SITE_PATTERN.fullmatch(name):
                raise ConfigError(f"Invalid target name: {name!r}")
            api = OPNsenseAPI(config)
            self._targets[name] = TargetState(
                api=api,
                savepoint_mgr=SavepointManager(api),
                config_cache=ConfigCache(),
            )

    @property
    def names(self) -> list[str]:
        """Return configured site names without exposing addresses or credentials."""
        return sorted(self._targets)

    def resolve(self, site: str = "") -> TargetState:
        """Look up a site; allow omission only with exactly one configured target."""
        if not site:
            if len(self._targets) != 1:
                raise TargetError("site is required when multiple OPNsense targets are configured")
            return next(iter(self._targets.values()))
        try:
            return self._targets[site]
        except KeyError as exc:
            raise TargetError(f"Unknown OPNsense site {site!r}; available: {', '.join(self.names)}") from exc

    async def close(self) -> None:
        """Close the connection pool of each configured firewall."""
        for state in self._targets.values():
            await state.api.close()

    @classmethod
    def from_environment(cls) -> TargetRegistry:
        """Read a TOML target inventory, or fall back to the original environment."""
        config_file = os.environ.get("OPNSENSE_TARGETS_FILE", "").strip()
        if not config_file:
            return cls({"default": load_config()})

        try:
            with Path(config_file).open("rb") as stream:
                document = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"Cannot read OPNSENSE_TARGETS_FILE: {exc}") from exc

        if set(document) != {"targets"} or not isinstance(document["targets"], dict):
            raise ConfigError("TOML must contain only a [targets] table")
        configs: dict[str, OPNsenseConfig] = {}
        for name, target in document["targets"].items():
            if not isinstance(target, dict) or not _SITE_PATTERN.fullmatch(name):
                raise ConfigError(f"Invalid target: {name!r}")
            if set(target) - _ALLOWED_FIELDS:
                raise ConfigError(f"Unknown configuration field for target {name!r}")
            for field in ("url", "api_key_env", "api_secret_env"):
                if not isinstance(target.get(field), str) or not target[field].strip():
                    raise ConfigError(f"Target {name!r} requires {field}")

            url = target["url"].strip().rstrip("/")
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path != "/api"
                or parsed.query
                or parsed.fragment
            ):
                raise ConfigError(f"Target {name!r} must use a fixed HTTPS URL ending in /api")
            try:
                port = parsed.port
            except ValueError as exc:
                raise ConfigError(f"Invalid HTTPS port for target {name!r}") from exc
            if port is not None and not (1 <= port <= 65535):
                raise ConfigError(f"Invalid HTTPS port for target {name!r}")

            key_env = target["api_key_env"]
            secret_env = target["api_secret_env"]
            if not _ENV_PATTERN.fullmatch(key_env) or not _ENV_PATTERN.fullmatch(secret_env):
                raise ConfigError(f"Invalid credential environment variable for target {name!r}")
            api_key = os.environ.get(key_env, "").strip()
            api_secret = os.environ.get(secret_env, "").strip()
            if not api_key or not api_secret:
                raise ConfigError(f"Missing credentials for target {name!r} (environment variables)")
            verify_ssl = target.get("verify_ssl", True)
            if not isinstance(verify_ssl, bool):
                raise ConfigError(f"verify_ssl must be boolean for target {name!r}")
            configs[name] = OPNsenseConfig(
                url=url,
                api_key=api_key,
                api_secret=api_secret,
                verify_ssl=verify_ssl,
                allow_writes=False,
            )
        return cls(configs)
