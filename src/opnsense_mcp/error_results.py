"""Present safe, machine-readable tool failures to MCP callers."""
from __future__ import annotations

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams

from opnsense_mcp.api_client import (
    BlockedEndpointError,
    OPNsenseAPIError,
    WriteDisabledError,
)
from opnsense_mcp.targets import TargetError
from opnsense_mcp.tool_audit import _label

_HTTP_CODES = {
    401: ("authentication_failed", "OPNsense rejected the configured API credentials"),
    403: ("permission_denied", "Configured OPNsense API credentials lack permission"),
    404: ("endpoint_not_found", "Requested API endpoint is unavailable on the target"),
    429: ("rate_limited", "Upstream API rate limit reached"),
}


def safe_error(exc: Exception) -> tuple[str, str, int | None]:
    """Never forward upstream response bodies or raw Python exception strings."""
    if isinstance(exc, WriteDisabledError):
        return "write_disabled", "Operation blocked by the read-only safety policy", None
    if isinstance(exc, BlockedEndpointError):
        return "operation_blocked", "Operation blocked by the reviewed endpoint policy", None
    if isinstance(exc, TargetError):
        return "invalid_site", "Unknown or ambiguous site; call opn_list_targets", None
    if isinstance(exc, OPNsenseAPIError):
        status = exc.status_code or None
        if status in _HTTP_CODES:
            code, message = _HTTP_CODES[status]
            return code, message, status
        if status is not None:
            return "upstream_http_error", f"Upstream returned HTTP {status}", status
        codes = {
            "connect_timeout": "TCP connection to configured target timed out",
            "read_timeout": "Timed out while waiting for the upstream response",
            "timeout": "Upstream request timed out",
            "connect_error": "TCP/DNS connection to configured upstream failed",
            "tls_hostname_mismatch": "Server certificate does not match the configured hostname or IP",
            "tls_certificate_expired": "Upstream server certificate has expired",
            "tls_certificate_not_yet_valid": "Upstream server certificate is not yet valid",
            "tls_untrusted_ca": "Server certificate chain is not trusted; check the mounted CA and chain",
            "tls_certificate_invalid": "Upstream server certificate validation failed",
            "tls_handshake_failed": "TLS handshake failed with configured upstream",
            "transport_error": "Upstream HTTP transport failed",
            "invalid_version_response": "OPNsense firmware version could not be parsed",
        }
        code = exc.code if exc.code in codes else "api_error"
        return code, codes.get(code, "OPNsense API operation failed"), None
    return "internal_error", "Internal MCP tool failure", None


class ErrorResultMiddleware(Middleware):
    """Turn expected upstream failures into explicit MCP isError tool results."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        try:
            return await call_next(context)
        except Exception as exc:
            code, message, status = safe_error(exc)
            args = getattr(context.message, "arguments", None)
            site = _label(args.get("site"), "(default)") if isinstance(args, dict) else "(default)"
            name = _label(getattr(context.message, "name", None), "(unknown)")
            return ToolResult(
                structured_content={
                    "ok": False,
                    "site": site,
                    "operation": name,
                    "error": {"type": code, "message": message, "http_status": status},
                },
                is_error=True,
            )
