"""Optional internal root CA layered onto the operating system certificate store."""
from __future__ import annotations

import os
import ssl


def validate_additional_ca(path: str) -> None:
    """Reject bad CA mounts before opening HTTP ports or creating API clients."""
    if not path:
        return
    if not os.path.isabs(path):
        raise ValueError("ADDITIONAL_CA_FILE must be an absolute container path")
    try:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cafile=path)
    except (OSError, ssl.SSLError, ValueError):
        raise ValueError("ADDITIONAL_CA_FILE is unreadable or contains no valid CA certificates") from None


def verification(verify_ssl: bool, additional_ca_file: str = "") -> bool | ssl.SSLContext:
    """HTTPS verification with normal CA roots plus a trusted additional PEM."""
    if not verify_ssl:
        return False
    if not additional_ca_file:
        return True
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=additional_ca_file)
    return ctx
