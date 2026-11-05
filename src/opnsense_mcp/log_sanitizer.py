"""Suppress FastMCP's raw traceback for errors already sanitized for MCP clients."""
from __future__ import annotations

import logging

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.targets import TargetError


class ExpectedToolErrorFilter(logging.Filter):
    """Keep genuine server exceptions; suppress raw upstream exception details."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info is None:
            return True
        current: BaseException | None = record.exc_info[1]
        visited: set[int] = set()
        while current is not None and id(current) not in visited:
            visited.add(id(current))
            if isinstance(current, (OPNsenseAPIError, TargetError)):
                return False
            current = current.__cause__ or current.__context__
        return True
