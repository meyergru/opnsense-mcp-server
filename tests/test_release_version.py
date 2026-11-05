"""Keep Python runtime, package metadata and release-notes versions aligned."""

import tomllib
from pathlib import Path

from opnsense_mcp import __version__


def test_package_version_matches_runtime() -> None:
    root = Path(__file__).resolve().parents[1]
    with (root / "pyproject.toml").open("rb") as config:
        project = tomllib.load(config)["project"]
    assert __version__ == project["version"]


def test_version_has_release_notes() -> None:
    root = Path(__file__).resolve().parents[1]
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{__version__}]" in changelog
