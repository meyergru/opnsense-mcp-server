# Streamable HTTP + Portainer deployment

Native FastMCP HTTP transport listens on port 8000 at `/mcp`. There is no
stdio-to-HTTP gateway, reverse proxy, database, or extra worker process.

## Review and build

1. Review the code and current CI results (lint, tests, security and Docker smoke).
2. Run **Publish reviewed MCP image to GHCR** manually on the `main`
   branch from GitHub Actions. The workflow publishes both
   `ghcr.io/meyergru/opnsense-mcp-server:dev` and a commit-specific
   `sha-<commit>` tag. No automatic publication occurs.
3. In Portainer on VM `mcp`, paste [compose.yaml](../compose.yaml) into a
   **Web editor** Stack and enter target/API credentials there. Do not
   commit real credentials to the public repository.
4. Allow OpenWebUI to reach the VM on TCP/8000; enforce an externally managed
   outbound allowlist of exact OPNsense API IP/port pairs before connecting
   real firewalls.

## Compose settings

All target addresses, credentials, and the MCP HTTP token are inline under
`services.opnsense-mcp.environment`. The server does not require a separate
TOML/secret file or writable data volume.

- `OPNSENSE_MCP_TRANSPORT=http` switches from legacy stdio to HTTP.
- `OPNSENSE_MCP_HOST=0.0.0.0` binds inside Docker.
- `OPNSENSE_MCP_PORT=8000` and the Docker `ports:` declaration expose the port.
- `OPNSENSE_MCP_MAX_RESULT_BYTES=16384`: bound all tool responses using native FastMCP middleware. Large results are truncated; narrow searches or lower limits when needed.
- `OPNSENSE_MCP_AUTH_TOKEN`: generate 32 random bytes as 64 hex chars with
  `openssl rand -hex 32`. The server rejects an absent/short token at startup.
- `OPNSENSE_SITES=local,remote` selects named OPNsense endpoints.
- `OPNSENSE_<NAME>_URL`, `_API_KEY`, `_API_SECRET`, `_VERIFY_SSL`: one set per site.
- `OPNSENSE_MCP_READ_ONLY=true` is the global default and disallows write-classified actions across all sites.
- `OPNSENSE_<NAME>_READ_ONLY` optionally overrides that setting per site. Set `false` **only** for a site that deliberately allows modifications; the default is safer.
- `OPNSENSE_ALLOW_WRITES` is a legacy single-target flag and does not govern named sites. The API client classifies endpoint operations individually; neither GET nor POST implies safety.

Use Portainer's Web editor rather than Git-backed Stack mode if you want
credentials directly in Compose **without committing them to the repository**.
Docker/Portainer administrators can read these environment values.
If a literal `$` appears in a credential, escape it as `$$` in Compose.

OpenWebUI should connect to `http://mcp:8000/mcp` (or the VM's actual
IP address). Configure the header `Authorization: Bearer <your token>`
on its MCP connection. The URI `mcp` resolves only if your internal DNS
provides it; Docker service names do not automatically resolve across VMs.

## Security / limitations

Plain HTTP sends the bearer token without TLS; only use this over your
trusted, firewall-restricted management network. TLS termination or a native
TLS listener should be considered if the network is not trusted.

The Compose container runs as an unprivileged UID with no capabilities,
a read-only root filesystem, a small tmpfs, and Watchtower opt-out.
These container settings do **not** replace host-enforced outbound firewalling.

**Security caveat:** The server blocks raw configuration exports and arbitrary
configuration sections over HTTP. Named targets are read-only by default; a central
allowlist restricts POST operations, and a response middleware suppresses
common credential-shaped fields. These defenses do **not** prove that
all plugin-specific responses are secret-safe. Use least-privileged
OPNsense API credentials and externally enforced network egress rules.
No live OPNsense integration testing has been completed.

## Local validation

Run `pytest`, `ruff check src/ tests/`, `ruff format --check src/ tests/`,
and `mypy src/`. A local smoke test can launch `opnsense-mcp`
with `OPNSENSE_MCP_TRANSPORT=http`, one named target, and the bearer token.
Without the header, the MCP endpoint must reject the request.

CI tests do not contact live firewalls. Docker smoke tests confirmed HTTP 401 without the bearer token and 200 with a valid token. A real OpenWebUI handshake test
requires both systems to be reachable in the DMZ.
