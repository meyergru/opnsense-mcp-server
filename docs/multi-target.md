# Native multi-target mode (development branch)

This fork supports **one MCP server process controlling several named OPNsense API
connections**. No external gateway or worker processes are required.

## Configuration

Create a local TOML file (do **not** commit real addresses or secrets):

```toml
[targets.local]
url = "https://10.10.0.1/api"
api_key_env = "OPN_LOCAL_KEY"
api_secret_env = "OPN_LOCAL_SECRET"
verify_ssl = true

[targets.remote]
url = "https://192.168.70.1:10443/api"
api_key_env = "OPN_REMOTE_KEY"
api_secret_env = "OPN_REMOTE_SECRET"
verify_ssl = true
```

The target names are model-visible; the API URLs and credentials are not included
in the target-list response. Set the environment variables in the service
environment (ideally from a root-owned systemd environment file):

```sh
export OPNSENSE_TARGETS_FILE=/etc/opnsense-mcp/targets.toml
export OPN_LOCAL_KEY=...
export OPN_LOCAL_SECRET=...
export OPN_REMOTE_KEY=...
export OPN_REMOTE_SECRET=...
```

All configured targets are **read-only** for this initial implementation
(`allow_writes=False`), regardless of `OPNSENSE_ALLOW_WRITES`. The
underlying API still needs a least-privilege OPNsense user on **each** firewall.

## Tool calls

- `opn_list_targets()` shows the configured site names.
- `opn_scan_config(site="local")` inventories the local firewall.
- `opn_list_kea_leases(site="remote", limit=20)` queries another firewall.
- All 81 original tools accept an optional `site` string.

When multiple sites exist, `site` **must** be provided: the server never
chooses a target implicitly. An unknown site is rejected. With one site, omission
continues to work. Existing `OPNSENSE_URL`, `OPNSENSE_API_KEY`, and
`OPNSENSE_API_SECRET` settings still work without a TOML file.

The configuration is loaded only when the server starts. A separate API client,
savepoint manager and configuration cache are allocated to each target. Shared
current-target state is never used.

## Security boundary

Targets are selected by fixed names, not arbitrary model-provided URLs.
Configuration requires HTTPS and a path ending in `/api`, and API secrets are
referenced by environment-variable name rather than stored in the TOML.

**This is not a network sandbox.** To defend against untrusted third-party code,
enforce an egress allowlist outside the LXC: only the exact OPNsense API
IP/port pairs, no general RFC1918 access, no unrestricted IPv6/DNS/Internet.
Restrict incoming MCP connections to the OpenWebUI host. Read-only API accounts,
redacted tool outputs, and a pinned dependency tree are separate safeguards.

This initial branch still uses upstream stdio transport. Direct authenticated
Streamable HTTP and output-bounding are later, separately testable changes.

## Testing

```sh
python -m pytest tests/test_targets.py tests/test_tools/test_registration.py -q
python -m pytest -q
```

No live firewall is required for the unit tests.