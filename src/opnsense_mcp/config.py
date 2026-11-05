"""Configuration management via environment variables.

Environment variables:
    OPNSENSE_URL: API base URL (required)
    OPNSENSE_API_KEY: API key (required)
    OPNSENSE_API_SECRET: API secret (required)
    OPNSENSE_VERIFY_SSL: Verify SSL certificate (default: true)
    OPNSENSE_ALLOW_WRITES: Enable legacy write operations (default: false)
    OPNSENSE_MCP_READ_ONLY: Default read-only policy for named targets (default: true)
    OPNSENSE_<SITE>_READ_ONLY: Optional site override of global read-only policy
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from opnsense_mcp.tls import validate_additional_ca

_TRUTHY = frozenset({"true", "1", "yes"})
_FALSY = frozenset({"false", "0", "no"})


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True, repr=False)
class OPNsenseConfig:
    """Immutable configuration loaded from environment variables."""

    url: str
    api_key: str
    api_secret: str
    verify_ssl: bool
    allow_writes: bool
    additional_ca_file: str = ""

    def __repr__(self) -> str:
        return f"OPNsenseConfig(url={self.url!r}, verify_ssl={self.verify_ssl}, allow_writes={self.allow_writes})"


def _parse_bool(value: str, var_name: str) -> bool:
    """Parse a boolean environment variable value.

    Accepts: true/false, 1/0, yes/no (case-insensitive).

    Raises:
        ConfigError: If the value is not a recognized boolean string.
    """
    lower = value.lower()
    if lower in _TRUTHY:
        return True
    if lower in _FALSY:
        return False
    msg = f"{var_name} must be true/false, 1/0, or yes/no (invalid value omitted)"
    raise ConfigError(msg)


def mcp_read_only_enabled(site: str = "") -> bool:
    """Resolve the global read-only default with an optional site override.

    The policy is loaded only when the server creates its target clients.
    Unknown/invalid boolean values are rejected at startup, not coerced.
    """
    global_name = "OPNSENSE_MCP_READ_ONLY"
    global_read_only = _parse_bool(os.environ.get(global_name, "true").strip(), global_name)
    if site:
        name = f"OPNSENSE_{site.upper().replace('.', '_')}_READ_ONLY"
        raw = os.environ.get(name)
        if raw is not None:
            return _parse_bool(raw.strip(), name)
    return global_read_only


def load_config() -> OPNsenseConfig:
    """Load and validate configuration from environment variables.

    Returns:
        Frozen dataclass with validated configuration.

    Raises:
        ConfigError: If required variables are missing or values are invalid.
    """
    missing: list[str] = []
    for var in ("OPNSENSE_URL", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"):
        if not os.environ.get(var, "").strip():
            missing.append(var)

    if missing:
        msg = f"Required environment variable(s) not set: {', '.join(missing)}"
        raise ConfigError(msg)

    url = os.environ["OPNSENSE_URL"].strip().rstrip("/")
    api_key = os.environ["OPNSENSE_API_KEY"].strip()
    api_secret = os.environ["OPNSENSE_API_SECRET"].strip()

    verify_ssl_raw = os.environ.get("OPNSENSE_VERIFY_SSL", "true").strip()
    verify_ssl = _parse_bool(verify_ssl_raw, "OPNSENSE_VERIFY_SSL")

    allow_writes_raw = os.environ.get("OPNSENSE_ALLOW_WRITES", "false").strip()
    allow_writes = _parse_bool(allow_writes_raw, "OPNSENSE_ALLOW_WRITES")
    # Explicit global read-only policy overrides the legacy single-target flag.
    # Without it, keep backward-compatible stdio behavior; HTTP cannot use
    # legacy single-target mode (enforced by TargetRegistry).
    if "OPNSENSE_MCP_READ_ONLY" in os.environ:
        allow_writes = not mcp_read_only_enabled()

    ca_file = os.environ.get("OPNSENSE_MCP_ADDITIONAL_CA_FILE", "").strip()
    validate_additional_ca(ca_file)

    return OPNsenseConfig(
        url=url,
        api_key=api_key,
        api_secret=api_secret,
        verify_ssl=verify_ssl,
        allow_writes=allow_writes,
        additional_ca_file=ca_file,
    )
