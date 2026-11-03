# Native multi-target mode

One MCP server process manages several named OPNsense API targets, without an external gateway or worker processes.

## Compose / Portainer configuration

All configuration, **including API keys and secrets**, comes from Docker Compose environment variables. No separate targets.toml or secrets mount is required.

Example Compose `environment:` section:

```yaml
environment:
  OPNSENSE_SITES: "local,remote"

  OPNSENSE_LOCAL_URL: "https://192.168.10.1/api"
  OPNSENSE_LOCAL_API_KEY: "replace-with-key"
  OPNSENSE_LOCAL_API_SECRET: "replace-with-secret"
  OPNSENSE_LOCAL_VERIFY_SSL: "true"

  OPNSENSE_MCP_READ_ONLY: "true"
  # Optional: allow writes only on one site (dangerous):
  # OPNSENSE_LOCAL_READ_ONLY: "false"

  OPNSENSE_REMOTE_URL: "https://192.168.20.1:10443/api"
  OPNSENSE_REMOTE_API_KEY: "replace-with-key"
  OPNSENSE_REMOTE_API_SECRET: "replace-with-secret"
  OPNSENSE_REMOTE_VERIFY_SSL: "true"
```

Target names start with a lower-case ASCII letter and support digits, underscores, and interior dots (up to 64 characters). Environment variable prefixes normalize dots to underscores and uppercase, e.g. `opnsense.mgsoft` uses `OPNSENSE_OPNSENSE_MGSOFT_URL`, `_API_KEY`, `_API_SECRET` and `_READ_ONLY`. `opnsense.mgsoft` and `opnsense_mgsoft` may not coexist because the environment prefixes collide. Duplicate names are rejected.

To include literal dollar signs inside Compose values, escape them as `$$`. Avoid committing a stack containing real credentials to a public Git repository. Portainer and users with Docker administration permissions can inspect the environment, including the secrets.

Each named target inherits `OPNSENSE_MCP_READ_ONLY=true` by default; override a specific site with `OPNSENSE_<SITE>_READ_ONLY=false` **only when explicitly permitting writes**. `OPNSENSE_ALLOW_WRITES` controls only legacy single-target configuration and does not override named target policy. Use separate least-privileged API users on each firewall. TLS verification defaults to true.

## MCP tools

- `opn_list_targets()` returns only site names, without URL or credentials.
- `opn_scan_config(site="local")` inventories one firewall.
- `opn_list_kea_leases(site="remote", limit=20)` queries a second firewall.
- All 81 upstream tools accept an optional `site` argument.

With multiple configured sites, the site parameter is mandatory for API operations, and there is no globally mutable current target. With one site, omission is allowed. When `OPNSENSE_SITES` is unset, the original single-site variables `OPNSENSE_URL`, `OPNSENSE_API_KEY`, and `OPNSENSE_API_SECRET` are still accepted.

The API client classifies every permitted call by its endpoint + action rather than trusting HTTP GET or POST. Unknown operations are denied **even on writable sites**. The registry allocates one API client, connection pool, savepoint manager, and configuration cache per target. Target names are fixed at service startup. The model cannot supply an arbitrary target URL.

## Transport and deployment status

The fork provides native **authenticated Streamable HTTP** at `/mcp`, with
a mandatory bearer token, configurable response limits and a basic
credential-field guard. Local stdio remains available.

Read [the main README](../README.md) and [HTTP/Portainer deployment](http-compose.md)
for current setup instructions. Live OPNsense integration has **not** yet been
verified; use least-privilege credentials and externally enforced egress rules.

The same reviewed image and Compose environment can move between Docker hosts
without changing application code.

## Security boundary

Enforce outbound firewall policy outside Docker: allow only the exact approved OPNsense API destinations/ports, and deny arbitrary RFC1918, DNS, IPv6 and public Internet egress. Code running in a container must not be able to modify these rules.

Moving the service onto the OpenWebUI VM is technically possible but weakens the threat boundary. Auditing our code does not fully exclude a compromised dependency or a malicious future update; keep the dedicated VM if the no-exfiltration requirement remains important.

## Testing

```sh
python -m pytest tests/test_targets.py tests/test_tools/test_registration.py -q
python -m pytest -q
```

These unit tests do not contact live firewalls.
