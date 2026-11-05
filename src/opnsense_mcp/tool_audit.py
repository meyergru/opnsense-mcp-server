"""Bounded tool audit: names/site aliases/status only, no arguments or results."""

from __future__ import annotations

import logging
import re
import time

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams

logger = logging.getLogger("opnsense_mcp.audit")
_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{0,99}\Z")


def _label(value: object, default: str) -> str:
    if isinstance(value, str) and _NAME.fullmatch(value):
        return value
    return default


class ToolAuditMiddleware(Middleware):
    """Log only registered tool name, bounded site alias, result, and duration."""

    def __init__(self, mode: str = "errors") -> None:
        if mode not in {"none", "errors", "all"}:
            raise ValueError("Invalid audit logging mode")
        self.mode = mode

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        if self.mode == "none":
            return await call_next(context)
        start = time.monotonic()
        name = _label(getattr(context.message, "name", None), "(invalid)")
        arguments = getattr(context.message, "arguments", None)
        site = _label(arguments.get("site"), "(default)") if isinstance(arguments, dict) else "(default)"
        try:
            result = await call_next(context)
        except Exception as exc:
            logger.warning(
                "tool=%s site=%s result=error error_class=%s duration_ms=%d",
                name,
                site,
                type(exc).__name__,
                round((time.monotonic() - start) * 1000),
            )
            raise
        status = "error" if getattr(result, "is_error", False) else "success"
        if status == "error":
            logger.warning(
                "tool=%s site=%s result=error duration_ms=%d",
                name,
                site,
                round((time.monotonic() - start) * 1000),
            )
        elif self.mode == "all":
            logger.info(
                "tool=%s site=%s result=success duration_ms=%d",
                name,
                site,
                round((time.monotonic() - start) * 1000),
            )
        return result
