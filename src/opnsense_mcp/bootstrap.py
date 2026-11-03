"""Minimal entrypoint: validate configuration before importing the MCP server.

No firewall network calls are made during preflight. The container can remain
alive but unhealthy on configuration errors, preventing Docker restart loops.
"""

from __future__ import annotations

import os
import sys
import time

from opnsense_mcp.config import ConfigError
from opnsense_mcp.targets import TargetRegistry
from opnsense_mcp.transport import load_transport_config


def validate_startup_configuration() -> None:
    """Check transport and all target variables before binding the MCP port."""
    load_transport_config()
    TargetRegistry.configs_from_environment()


def main() -> None:
    """Start the server or report exactly one actionable configuration error."""
    try:
        validate_startup_configuration()
    except (ConfigError, ValueError) as exc:
        print(f"OPNsense MCP CONFIGURATION ERROR: {exc}", file=sys.stderr, flush=True)
        if os.environ.get("OPNSENSE_MCP_CONFIG_ERROR_HOLD", "").strip().lower() in {"true", "1", "yes"}:
            print(
                "MCP server NOT started. Fix the Portainer Compose variables and redeploy. "
                "Container stays alive but unhealthy to avoid Docker restart loops.",
                file=sys.stderr,
                flush=True,
            )
            while True:
                time.sleep(3600)
        print("MCP server NOT started. Fix the configuration and restart.", file=sys.stderr, flush=True)
        raise SystemExit(2) from None

    # Import only after validation: server.py constructs the FastMCP auth
    # provider at import time and would otherwise emit a Python traceback.
    from opnsense_mcp.server import main as server_main

    server_main()


if __name__ == "__main__":
    main()
