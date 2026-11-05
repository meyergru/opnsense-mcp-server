"""Conservative HTTPX/TLS error classification; never expose exception strings."""
from __future__ import annotations

import ssl

import httpx


def classify_transport_error(exc: httpx.HTTPError) -> tuple[str, str]:
    """Return a stable diagnostic code and secret-free user-facing explanation."""
    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout", "TCP connection to configured target timed out"
    if isinstance(exc, httpx.ReadTimeout):
        return "read_timeout", "Timed out while waiting for the upstream response"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout", "Upstream request timed out"

    # HTTPX wraps OpenSSL errors in httpcore/HTTPX exceptions. Examine causal
    # metadata only; never forward str(exc), which may contain request details.
    seen: set[int] = set()
    current: BaseException | None = exc
    chain: list[BaseException] = []
    while current is not None and id(current) not in seen and len(chain) < 16:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__

    for cause in chain:
        if isinstance(cause, ssl.SSLCertVerificationError):
            code = getattr(cause, "verify_code", None)
            reason = (str(getattr(cause, "verify_message", "")) + " " + str(cause)).lower()
            if code in (62, 64) or "hostname mismatch" in reason or "ip address mismatch" in reason:
                return "tls_hostname_mismatch", "Server certificate does not match the configured hostname or IP"
            if code == 10 or "certificate has expired" in reason:
                return "tls_certificate_expired", "Upstream server certificate has expired"
            if code == 9 or "not yet valid" in reason:
                return "tls_certificate_not_yet_valid", "Upstream server certificate is not yet valid"
            if code in (18, 19, 20, 21) or "unable to get local issuer" in reason:
                return "tls_untrusted_ca", "Server certificate chain is not trusted; check the mounted CA and chain"
            return "tls_certificate_invalid", "Upstream server certificate validation failed"
    for cause in chain:
        if isinstance(cause, ssl.SSLError):
            return "tls_handshake_failed", "TLS handshake failed with configured upstream"

    # Some httpcore versions flatten an SSL failure into ConnectError.text.
    # Only detect fixed markers; do not expose the underlying arbitrary text.
    if any("certificate_verify_failed" in str(cause).lower() for cause in chain):
        return "tls_certificate_invalid", "Upstream server certificate validation failed"

    if isinstance(exc, httpx.ConnectError):
        return "connect_error", "TCP/DNS connection to configured upstream failed"
    if isinstance(exc, httpx.HTTPError):
        return "transport_error", "Upstream HTTP transport failed"
    return "transport_error", "Upstream request failed"
