# Streamable HTTP + Portainer deployment (development)

Native FastMCP HTTP transport listens on port 8000 at `/mcp`. There is no
stdio-to-HTTP gateway, reverse proxy, database, or extra worker process.

## Review and build

1. Review the PR and require all three CI jobs (lint, tests, security) to pass.
2. Merge to `main` when approved.
3. In GitHub Actions, manually run **Publish reviewed MCP image to GHCR**
   on the `main` branch. This publishes `ghcr.io/meyergru/opnsense-mcp-server:dev`
   and a `sha-<commit>` tag. No build runs automatically on commits or tags.
4. In Portainer on VM `mcp`, create a new **Web editor** Stack by copying
   `compose.yaml`. Fill in credentials there; do NOT commit them to public Git.
5. Allow the OpenWebUI host to reach VM `mcp` on TCP/8000. Restrict that
   inbound port at the VM/Proxmox firewall. Explicitly restrict the VM's
   outbound traffic to the configured OPNsense IP/port pairs.

## Compose settings

All target addresses, credentials, and the MCP HTTP token are inline under
`services.opnsense-mcp.environment`. The server does not require a separate
TOML/secret file or writable data volume.

- `OPNSENSE_MCP_TRANSPORT=http` switches from legacy stdio to HTTP.
- `OPNSENSE_MCP_HOST=0.0.0.0` binds inside Docker.
- `OPNSENSE_MCP_PORT=8000` and the Docker `ports:` declaration expose the port.
- `OPNSENSE_MCP_AUTH_TOKEN`: generate 32 random bytes as 64 hex chars with
  `openssl rand -hex 32`. The server rejects an absent/short token at startup.
- `OPNSENSE_SITES=local,remote` selects named OPNsense endpoints.
- `OPNSENSE_<NAME>_URL`, `_API_KEY`, `_API_SECRET`, `_VERIFY_SSL`: one set per site.
- `OPNSENSE_ALLOW_WRITES` has no effect on named target profiles: they are
  forced read-only in the current implementation.

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

**Do not deploy to production yet.** Although the HTTP listener is authenticated,
upstream raw configuration tools and the per-endpoint read/write policy still
need a fail-closed security review to ensure no secrets or mutations leak
through MCP. API users must independently have read-only OPNsense privileges.

## Local validation

Run `pytest`, `ruff check src/ tests/`, `ruff format --check src/ tests/`,
and `mypy src/`. A local smoke test can launch `python -m opnsense_mcp`
with `OPNSENSE_MCP_TRANSPORT=http`, one named target, and the bearer token.
Without the header, the MCP endpoint must reject the request.

CI tests do not contact live firewalls. A real OpenWebUI handshake test
requires both systems to be reachable in the DMZ.
