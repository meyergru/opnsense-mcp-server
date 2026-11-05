"""Regression checks for path-suffix authorization and HTTPX URL normalization."""

from __future__ import annotations

import pytest

from opnsense_mcp.api_client import OPNsenseAPI


@pytest.mark.parametrize(
    "suffix",
    [
        ".",
        "..",
        "object/../admin",
        "object/./admin",
        "../core/system/reboot",
        "object//other",
        "/object",
        "object/",
        "object\\other",
        "object%2fother",
        "%2e%2e",
        "object%252fother",
        "object?query=yes",
        "object#fragment",
        "object\nheader",
        "object with spaces",
        "https://example.invalid/api",
        "fe80::1%eth0",
    ],
)
@pytest.mark.parametrize(
    ("method", "endpoint"),
    [
        ("get", "haproxy.settings.get_frontend"),
        ("post", "fw26.filter.toggle"),
    ],
)
async def test_reject_ambiguous_suffix_without_http_io(
    mock_config_writes, mock_httpx_client, method, endpoint, suffix
):
    api = OPNsenseAPI(mock_config_writes)
    api._client = mock_httpx_client
    # The invalid suffix must be rejected even before lazy version detection.
    with pytest.raises(ValueError, match="Invalid API path suffix"):
        await getattr(api, method)(endpoint, path_suffix=suffix)
    mock_httpx_client.get.assert_not_called()
    mock_httpx_client.post.assert_not_called()


@pytest.mark.parametrize(
    ("endpoint", "suffix"),
    [
        ("mvc.kea.leases.del", "2001:db8::123"),
        ("fw26.filter.toggle", "11111111-1111-4111-8111-111111111111/1"),
        (
            "fw26.filter.move",
            "11111111-1111-4111-8111-111111111111,"
            "22222222-2222-4222-8222-222222222222/"
            "33333333-3333-4333-8333-333333333333",
        ),
    ],
)
async def test_allow_reviewed_composite_suffixes(mock_config_writes, mock_httpx_client, endpoint, suffix):
    api = OPNsenseAPI(mock_config_writes)
    api._client = mock_httpx_client
    api._detected_version = (26, 7)
    api._use_snake_case = True
    await api.post(endpoint, path_suffix=suffix)
    assert mock_httpx_client.post.await_args.args[0].endswith("/" + suffix)
    mock_httpx_client.get.assert_not_called()


async def test_empty_suffix_remains_allowed(mock_config_writes, mock_httpx_client):
    api = OPNsenseAPI(mock_config_writes)
    api._client = mock_httpx_client
    api._detected_version = (26, 7)
    api._use_snake_case = True
    await api.post("firewall.apply", path_suffix="")
    assert not mock_httpx_client.post.await_args.args[0].endswith("/")


def test_httpx_normalizes_dot_segments():
    """Document why rejecting dot segments before creating a request matters."""
    import httpx

    url = httpx.URL("https://fw.example/api/haproxy/settings/getServer/../reconfigure")
    assert url.path == "/api/haproxy/settings/reconfigure"
