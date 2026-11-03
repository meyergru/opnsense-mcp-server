"""Named OPNsense targets with separate API clients and caches.

Multi-target inventory and credentials are passed entirely via environment
variables, for example from a Docker Compose 'environment:' section.

OPNSENSE_SITES=local,remote
OPNSENSE_LOCAL_URL=https://10.0.0.1/api
OPNSENSE_LOCAL_API_KEY=...
OPNSENSE_LOCAL_API_SECRET=...

Omitting OPNSENSE_SITES preserves upstream single-target configuration.
Names are fixed at startup: MCP callers cannot supply arbitrary host URLs.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config import ConfigError, OPNsenseConfig, load_config, mcp_read_only_enabled
from opnsense_mcp.config_cache import ConfigCache

_SITE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class TargetError(ValueError):
    """Unknown target or ambiguous target selection."""


@dataclass
class TargetState:
    """Independent state for one firewall."""

    api: OPNsenseAPI
    savepoint_mgr: SavepointManager
    config_cache: ConfigCache


def _check_url(url: str, name: str) -> str:
    """Validate a fixed upstream API URL without accepting embedded credentials."""
    url = url.strip().rstrip("/")
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"Invalid HTTPS port for target {name!r}") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/api"
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ConfigError(f"Target {name!r} must have a fixed HTTPS URL ending in /api")
    return url


class TargetRegistry:
    """Mapping from fixed site names to independent firewall clients and caches."""

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
        """Return site names only; never return URLs or credentials."""
        return sorted(self._targets)

    def resolve(self, site: str = "") -> TargetState:
        """Look up a site; allow omission only for exactly one target."""
        if not site:
            if len(self._targets) != 1:
                raise TargetError("site is required when multiple OPNsense targets are configured")
            return next(iter(self._targets.values()))
        try:
            return self._targets[site]
        except KeyError as exc:
            raise TargetError(f"Unknown OPNsense site {site!r}; available: {', '.join(self.names)}") from exc

    async def close(self) -> None:
        """Close the independent connection pool for every target."""
        for state in self._targets.values():
            await state.api.close()

    @classmethod
    def from_environment(cls) -> TargetRegistry:
        """Create target clients from Docker Compose-style environment variables."""
        sites_raw = os.environ.get("OPNSENSE_SITES", "").strip()
        if not sites_raw:
            if os.environ.get("OPNSENSE_MCP_TRANSPORT", "stdio").strip().lower() == "http":
                raise ConfigError("HTTP mode requires OPNSENSE_SITES for explicit per-site policy")
            return cls({"default": load_config()})

        names = [name.strip() for name in sites_raw.split(",")]
        if any(not _SITE_PATTERN.fullmatch(name) for name in names):
            raise ConfigError("OPNSENSE_SITES must be comma-separated lower-case names (a-z, 0-9, _)")
        if len(set(names)) != len(names):
            raise ConfigError("OPNSENSE_SITES must not contain duplicate site names")

        configs: dict[str, OPNsenseConfig] = {}
        for name in names:
            prefix = f"OPNSENSE_{name.upper()}_"
            required = ("URL", "API_KEY", "API_SECRET")
            values = {part: os.environ.get(prefix + part, "").strip() for part in required}
            if not all(values.values()):
                missing = [prefix + part for part in required if not values[part]]
                raise ConfigError(f"Missing configuration variable(s): {', '.join(missing)}")
            ssl_value = os.environ.get(prefix + "VERIFY_SSL", "true").strip().lower()
            if ssl_value not in {"true", "false"}:
                raise ConfigError(f"{prefix}VERIFY_SSL must be true or false")
            configs[name] = OPNsenseConfig(
                url=_check_url(values["URL"], name),
                api_key=values["API_KEY"],
                api_secret=values["API_SECRET"],
                verify_ssl=ssl_value == "true",
                allow_writes=not mcp_read_only_enabled(name),
            )
        return cls(configs)
