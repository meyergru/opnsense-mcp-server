"""Reusable self-describing types for MCP tool input parameters.

Site names are configured per deployment, so they cannot be a fixed enum.
Tools instruct agents to discover them through opn_list_targets instead.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

SiteName = Annotated[
    str,
    Field(
        description=(
            "Configured OPNsense target site name, not a hostname or URL. "
            "Call opn_list_targets to discover exact valid names. "
            "Empty string selects the configured default site, if any."
        )
    ),
]


RequiredSiteName = Annotated[
    str,
    Field(
        min_length=1,
        description=(
            "REQUIRED nonempty exact OPNsense target site alias. "
            "Call opn_list_targets to discover valid names, then pass one explicitly. "
            "Never omit site or pass an empty string, including single-target deployments."
        ),
    ),
]
