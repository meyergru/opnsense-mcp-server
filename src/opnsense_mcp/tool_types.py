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
            "Empty string selects the sole site only when exactly one target is configured. "
            "With multiple targets, site must be the exact nonempty name from opn_list_targets."
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


BoundedFirmwareChecks = Annotated[
    int,
    Field(
        ge=1,
        le=3,
        description="Number of firmware/audit status polls, an integer from 1 to 3 inclusive.",
    ),
]

BoundedFirmwarePollInterval = Annotated[
    int,
    Field(
        ge=1,
        le=3,
        description="Seconds between firmware/audit polls, an integer from 1 to 3 inclusive.",
    ),
]
