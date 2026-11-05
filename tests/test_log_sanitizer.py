"""Never render raw expected upstream exceptions in FastMCP's logger."""

from __future__ import annotations

import logging

from opnsense_mcp.api_client import OPNsenseAPIError
from opnsense_mcp.log_sanitizer import ExpectedToolErrorFilter


def _record(error: BaseException) -> logging.LogRecord:
    return logging.LogRecord(
        "fastmcp.server.server", logging.ERROR, __file__, 1,
        "Error calling tool", (), (type(error), error, None),
    )


def test_filter_discards_known_upstream_traceback_wrapped_by_fastmcp() -> None:
    api = OPNsenseAPIError("SECRET=never-log", code="tls_hostname_mismatch")
    wrapper = RuntimeError("opaque framework wrapper")
    wrapper.__cause__ = api
    assert ExpectedToolErrorFilter().filter(_record(wrapper)) is False


def test_filter_does_not_hide_unexpected_programming_errors() -> None:
    assert ExpectedToolErrorFilter().filter(_record(RuntimeError("bug"))) is True
