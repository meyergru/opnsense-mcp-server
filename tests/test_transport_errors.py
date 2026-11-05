"""Regression coverage for TLS certificate failures that must reach MCP callers."""
from __future__ import annotations

import ssl

import httpx
import pytest

from opnsense_mcp.transport_errors import classify_transport_error


def _wrapped_cert_error(detail: str) -> httpx.ConnectError:
    try:
        raise ssl.SSLCertVerificationError(detail)
    except ssl.SSLCertVerificationError as ssl_error:
        try:
            raise httpx.ConnectError("SECRET=never-expose-this") from ssl_error
        except httpx.ConnectError as error:
            return error


@pytest.mark.parametrize(
    ("reason", "category"),
    [
        ("Hostname mismatch, certificate not valid for opnsense.thomas", "tls_hostname_mismatch"),
        ("certificate has expired", "tls_certificate_expired"),
        ("unable to get local issuer certificate", "tls_untrusted_ca"),
        ("certificate verify failed", "tls_certificate_invalid"),
    ],
)
def test_classify_certificate_errors_without_leaking_details(reason: str, category: str) -> None:
    code, message = classify_transport_error(_wrapped_cert_error(reason))
    assert code == category
    assert "SECRET" not in message
    assert "opnsense.thomas" not in message


def test_classify_timeouts_without_leaking_details() -> None:
    code, message = classify_transport_error(httpx.ConnectTimeout("PASSWORD=untrusted"))
    assert code == "connect_timeout"
    assert "PASSWORD" not in message
