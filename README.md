# OPNsense MCP Server

A Python [FastMCP](https://gofastmcp.com/) server for connecting MCP-compatible AI clients, including **OpenWebUI**, to several **named OPNsense firewalls** over their REST APIs. This is a fork of [lucamarien/opnsense-mcp-server](https://github.com/lucamarien/opnsense-mcp-server), with the original MIT license retained.

**83 tools:** 81 upstream tools plus `opn_list_targets` and `opn_check_firmware_updates`; see the [tool reference](#available-tools-82).

## Architecture and configuration ownership

The recommended deployment is **one Docker container** on a separate VM, using native authenticated **Streamable HTTP**. No additional gateway, reverse proxy, worker or database is required.

```text
OpenWebUI / other MCP client
  http://mcp:8000/mcp + Authorization: Bearer <MCP_TOKEN>
                |
                v
MCP VM / Docker / FastMCP
  Compose holds OPNsense URLs and API credentials
  site="local"  -> dedicated API client/cache -> OPNsense A
  site="remote" -> dedicated API client/cache -> OPNsense B
```

**The client configures only the MCP URL and its bearer token.** OPNsense addresses and API key/secret pairs are configured on the **MCP server**, via Docker Compose environment variables. The client selects a preconfigured target by the `site` tool argument, never by a caller-supplied URL.

When multiple sites are configured, `site` is required on every OPNsense operation. With exactly one site it can be omitted. All 81 original tools accept `site`.

## Requirements / current state

- Docker/Portainer for recommended deployment, or Python **3.11+** for local stdio.
- OPNsense **24.7+** per upstream's stated compatibility; this fork targets **26.7+**, but **has not yet been live-tested against an OPNsense**.
- HTTPS reachability to each OPNsense API and a dedicated least-privilege API user/token per site.
- A firewall policy restricting the MCP VM's outbound connections to approved OPNsense IP/port pairs.

CI runs pytest, Ruff, mypy, security/dependency checks and a real Docker HTTP smoke test. The latter confirmed **401 without a bearer token** and **200 with a valid token**. These are integration tests of the MCP container, **not** of live firewall behavior or complete secret filtering.

## Quick start: Portainer / Docker Compose

1. Create separate, least-privilege **read-only API credentials** on each OPNsense firewall.
2. Review [compose.yaml](compose.yaml), then paste it into a **Portainer Web editor Stack** (not a Git-backed Stack) on your dedicated `mcp` VM.
3. Configure `OPNSENSE_SITES` and the matching `OPNSENSE_<SITE>_URL`, `_API_KEY`, `_API_SECRET`, `_VERIFY_SSL` variables in the Stack. No separate TOML or secrets files are required.
4. Generate a random 64-character hexadecimal MCP token with `openssl rand -hex 32`; enter it as `OPNSENSE_MCP_AUTH_TOKEN`.
5. If needed, publish the reviewed `main` image using the **manual** [GHCR workflow](.github/workflows/publish-ghcr.yml). It publishes `ghcr.io/meyergru/opnsense-mcp-server:dev` and `sha-<commit>` tags. No image is published by ordinary commits or version tags. Prefer an explicit SHA-tag for deployment.
6. Before starting against live firewalls, enforce VM-level inbound and outbound restrictions and the OPNsense API privileges.
7. In OpenWebUI, configure a **Streamable HTTP MCP** connection to `http://<mcp-host>:8000/mcp` with header `Authorization: Bearer <MCP_TOKEN>`. Internal DNS must resolve `mcp` if you use that hostname.
8. Use `opn_list_targets()`, then a harmless check such as `opn_system_status(site="local")`.

Representative **Compose environment section** (placeholder credentials only):

```yaml
environment:
  OPNSENSE_MCP_TRANSPORT: "http"
  OPNSENSE_MCP_HOST: "0.0.0.0"
  OPNSENSE_MCP_PORT: "8000"
  OPNSENSE_MCP_MAX_RESULT_BYTES: "16384"
  OPNSENSE_MCP_READ_ONLY: "true"
  OPNSENSE_MCP_AUTH_TOKEN: "replace-with-64-random-hex-characters"

  OPNSENSE_SITES: "local,remote"
  OPNSENSE_LOCAL_URL: "https://192.168.10.1/api"
  OPNSENSE_LOCAL_API_KEY: "replace-with-key"
  OPNSENSE_LOCAL_API_SECRET: "replace-with-secret"
  OPNSENSE_LOCAL_VERIFY_SSL: "true"
  # OPNSENSE_LOCAL_READ_ONLY: "true"  # optional

  OPNSENSE_REMOTE_URL: "https://192.168.20.1:10443/api"
  OPNSENSE_REMOTE_API_KEY: "replace-with-key"
  OPNSENSE_REMOTE_API_SECRET: "replace-with-secret"
  OPNSENSE_REMOTE_VERIFY_SSL: "true"
```

**Inline credentials are an explicit deployment choice.** Portainer and Docker administrators can inspect them. Keep the *real* Stack out of a public Git repository. If a credential contains `$`, escape it as `$$` in Compose. No actual credentials are present in this repository.

### Configuration reference

| Setting | Default | Purpose |
| --- | --- | --- |
| `OPNSENSE_MCP_TRANSPORT` | `stdio` | Set to `http` for native Streamable HTTP. |
| `OPNSENSE_MCP_HOST` | `127.0.0.1` | HTTP bind address; Compose explicitly uses `0.0.0.0` inside Docker. |
| `OPNSENSE_MCP_PORT` | `8000` | HTTP port. |
| `OPNSENSE_MCP_AUTH_TOKEN` | *none* | Required for HTTP; 32–256 permitted ASCII token characters. |
| `OPNSENSE_MCP_MAX_RESULT_BYTES` | `16384` | Tool response limit, 1,024–131,072 bytes. |
| `OPNSENSE_MCP_READ_ONLY` | `true` | Global read-only policy for all named targets. |
| `OPNSENSE_<SITE>_READ_ONLY` | *inherits global* | Optional per-site override (`true` / `false`). |
| `OPNSENSE_SITES` | *unset* | Comma-separated names, e.g. `local,remote`. |
| `OPNSENSE_<SITE>_URL` | *required* | HTTPS URL ending in `/api`, optional nonstandard port. |
| `OPNSENSE_<SITE>_API_KEY` | *required* | API key of this target. |
| `OPNSENSE_<SITE>_API_SECRET` | *required* | API secret of this target. |
| `OPNSENSE_<SITE>_VERIFY_SSL` | `true` | Verify the HTTPS certificate. |

Site aliases start with a lower-case letter and may contain lower-case letters, digits and underscores; variable prefixes use upper case (`local` → `OPNSENSE_LOCAL_URL`). Named targets inherit `OPNSENSE_MCP_READ_ONLY=true` by default, with optional per-site overrides. `OPNSENSE_ALLOW_WRITES` is legacy-only and does not control named targets.

### Local stdio mode (optional)

The upstream `stdio` mode still works for clients that start the MCP process themselves. Without `OPNSENSE_SITES`, the original `OPNSENSE_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`, `OPNSENSE_VERIFY_SSL` and `OPNSENSE_ALLOW_WRITES` variables remain supported.

```bash
git clone https://github.com/meyergru/opnsense-mcp-server.git
cd opnsense-mcp-server
python -m pip install -e .

OPNSENSE_URL="https://192.168.10.1/api" \
OPNSENSE_API_KEY="replace-with-key" \
OPNSENSE_API_SECRET="replace-with-secret" \
opnsense-mcp
```

Do **not** use the original author's `uhlenheide` Docker Hub image for this fork.

## Available Tools (83)

### Target selection (1 tool)

| Tool | Description |
| --- | --- |
| `opn_list_targets` | List configured site aliases, without returning addresses or credentials. |

### System (8 tools)

| Tool | Description |
| --- | --- |
| `opn_system_status` | System info and last cached firmware status (**GET**, does not trigger a fresh update check) |
| `opn_check_firmware_updates` | Refresh firmware update status via **POST** `/api/core/firmware/status` (no package installation or reboot). Queries configured mirrors, updates check metadata; can take several seconds. |
| `opn_list_services` | List all services and their running status. Params: `search`, `limit` |
| `opn_gateway_status` | Gateway availability, latency, and dpinger health checks |
| `opn_download_config` | Raw `config.xml` export; **blocked for HTTP clients**. Legacy stdio only. |
| `opn_scan_config` | Scan the full configuration, parse it into sections, and collect runtime inventory (firmware, plugins, DHCP, DNS, interfaces, services). Results are cached separately per site. Params: `force` |
| `opn_get_config_section` | Raw config-section lookup; **blocked for HTTP clients**. Legacy stdio only. |
| `opn_mcp_info` | MCP server version, write mode status, detected OPNsense version, API style, and whether firewall writes still get savepoint/rollback protection |

### Network (5 tools)

| Tool | Description |
| --- | --- |
| `opn_interface_stats` | Per-interface traffic statistics (bytes in/out, packets, errors) |
| `opn_arp_table` | ARP table showing IP-to-MAC address mappings |
| `opn_ndp_table` | NDP (Neighbor Discovery Protocol) table showing IPv6-to-MAC address mappings |
| `opn_ipv6_status` | IPv6 configuration and address status for all interfaces (method, live addresses, summary) |
| `opn_list_static_routes` | Configured static routes. Params: `search`, `limit` |

### Firewall (21 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_firewall_rules` | List MVC firewall filter rules. Params: `search`, `limit` | No |
| `opn_list_firewall_aliases` | List alias definitions (IP lists, port groups, GeoIP, URLs). Params: `search`, `limit` | No |
| `opn_list_nat_rules` | List NAT port forwarding (DNAT) rules. Params: `search`, `limit` | No |
| `opn_list_firewall_categories` | List firewall rule categories and their UUIDs. Params: `search`, `limit` | No |
| `opn_firewall_log` | Recent firewall log entries with client-side filtering. Params: `source_ip`, `destination_ip`, `action`, `interface`, `limit` | No |
| `opn_confirm_changes` | Confirm pending changes, cancelling 60-second auto-rollback (OPNsense < 26.7; a no-op returning `not_applicable` on 26.7+). Params: `revision` | Yes |
| `opn_toggle_firewall_rule` | Toggle a rule's enabled/disabled state with savepoint (OPNsense < 26.7). Params: `uuid` | Yes |
| `opn_add_firewall_rule` | Create a new filter rule with savepoint (OPNsense < 26.7). Params: `action`, `direction`, `interface`, `ip_protocol`, `protocol`, `source_net`, `destination_net`, `destination_port`, `description` | Yes |
| `opn_delete_firewall_rule` | Delete a filter rule by UUID with savepoint (OPNsense < 26.7). Params: `uuid` | Yes |
| `opn_add_alias` | Create a new alias. Params: `name`, `alias_type`, `content`, `description` | Yes |
| `opn_add_nat_rule` | Create a NAT port forwarding rule with savepoint (OPNsense < 26.7). Params: `destination_port`, `target_ip`, `interface`, `protocol`, `target_port`, `description` | Yes |
| `opn_add_firewall_category` | Create a new firewall rule category. Params: `name`, `color` | Yes |
| `opn_delete_firewall_category` | Delete a firewall rule category by UUID with savepoint (OPNsense < 26.7). Params: `uuid` | Yes |
| `opn_set_rule_categories` | Assign categories to a firewall rule with savepoint (OPNsense < 26.7). Params: `uuid`, `categories` | Yes |
| `opn_add_icmpv6_rules` | Create essential ICMPv6 rules required for IPv6 operation (NDP, RA, ping6) per RFC 4890. Params: `interface` | Yes |
| `opn_update_alias` | Update an existing alias (name, content, type, description). Read-modify-write. Params: `uuid`, `name`, `content`, `description`, `alias_type`, `enabled` | Yes |
| `opn_delete_alias` | Delete an alias by UUID. Check rule references first. Params: `uuid` | Yes |
| `opn_toggle_alias` | Toggle alias enabled/disabled state. Params: `uuid` | Yes |
| `opn_update_firewall_rule` | Update filter rule fields with savepoint (OPNsense < 26.7). Params: `uuid`, `action`, `direction`, `interface`, `ip_protocol`, `protocol`, `source_net`, `source_not`, `source_port`, `destination_net`, `destination_not`, `destination_port`, `gateway`, `log`, `quick`, `sequence`, `categories`, `description`, `enabled` | Yes |
| `opn_update_nat_rule` | Update NAT port forwarding rule with savepoint (OPNsense < 26.7). Params: `uuid`, `interface`, `protocol`, `destination_port`, `target_ip`, `target_port`, `description`, `enabled` | Yes |
| `opn_delete_nat_rule` | Delete a NAT port forwarding rule by UUID with savepoint (OPNsense < 26.7). Params: `uuid` | Yes |

> **Note:** Named targets are always read-only. The older savepoint functionality applies only to legacy write-enabled stdio configurations.

### DNS (13 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_dns_overrides` | Unbound host overrides (local DNS records). Params: `search`, `limit` | No |
| `opn_list_dns_forwards` | DNS forward zones (domain-specific servers). Params: `search`, `limit` | No |
| `opn_dns_stats` | Unbound resolver statistics (queries, cache hits, uptime) | No |
| `opn_reconfigure_unbound` | Apply pending DNS resolver configuration changes | Yes |
| `opn_add_dns_override` | Add an Unbound DNS host override (A/AAAA record) and apply immediately. Params: `hostname`, `domain`, `server`, `description` | Yes |
| `opn_list_dnsbl` | List DNSBL blocklist configurations with providers and status. Params: `search`, `limit` | No |
| `opn_get_dnsbl` | Get full DNSBL configuration by UUID (providers, allowlists, settings). Params: `uuid` | No |
| `opn_set_dnsbl` | Update DNSBL settings (read-modify-write). Params: `uuid`, `enabled`, `providers`, `allowlists`, `blocklists`, `wildcards`, etc. | Yes |
| `opn_add_dnsbl_allowlist` | Add domains to DNSBL allowlist without overwriting. Params: `uuid`, `domains` | Yes |
| `opn_remove_dnsbl_allowlist` | Remove domains from DNSBL allowlist. Params: `uuid`, `domains` | Yes |
| `opn_update_dnsbl` | Reload DNSBL blocklist files and restart Unbound (no config change, recovery tool) | Yes |
| `opn_update_dns_override` | Update an Unbound DNS host override and apply immediately. Params: `uuid`, `hostname`, `domain`, `server`, `description`, `enabled` | Yes |
| `opn_delete_dns_override` | Delete an Unbound DNS host override and apply immediately. Params: `uuid` | Yes |

### DHCP (8 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_dhcp_leases` | Active DHCPv4 leases from the ISC DHCP server | No |
| `opn_list_kea_leases` | DHCPv4 leases from the Kea DHCP server. Params: `search`, `limit` | No |
| `opn_list_dnsmasq_leases` | DHCPv4 and DHCPv6 leases from the dnsmasq DNS/DHCP server. Params: `search`, `limit` | No |
| `opn_list_dnsmasq_ranges` | Configured DHCP address ranges (both DHCPv4 and DHCPv6 with RA config). Params: `search`, `limit` | No |
| `opn_add_dnsmasq_range` | Create a new DHCP range (IPv4 or IPv6 with Router Advertisement configuration). Params: `interface`, `start_addr`, `end_addr`, `prefix_len`, `ra_mode`, `lease_time`, `description` | Yes |
| `opn_reconfigure_dnsmasq` | Apply pending dnsmasq DNS/DHCP configuration changes | Yes |
| `opn_update_dnsmasq_range` | Update a DHCP range (addresses, lease time, RA config) and apply. Params: `uuid`, `interface`, `start_addr`, `end_addr`, `prefix_len`, `ra_mode`, `lease_time`, `description`, `enabled` | Yes |
| `opn_delete_dnsmasq_range` | Delete a DHCP range by UUID and apply. Params: `uuid` | Yes |

### VPN (3 tools)

| Tool | Description |
| --- | --- |
| `opn_wireguard_status` | WireGuard tunnel and peer status (requires os-wireguard plugin) |
| `opn_ipsec_status` | IPsec VPN tunnel status — IKE (Phase 1) and ESP/AH (Phase 2) sessions |
| `opn_openvpn_status` | OpenVPN connection status — instances, sessions, and routes |

### HAProxy (8 tools)

HAProxy inspection and legacy administration tools (requires os-haproxy plugin). Writes are blocked for named targets.

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_haproxy_status` | HAProxy service status and backend health | No |
| `opn_haproxy_search` | Search HAProxy resources by type. Params: `resource_type` (frontends/backends/servers/actions/acls/healthchecks/errorfiles/resolvers/mailers), `search`, `limit` | No |
| `opn_haproxy_get` | Get detailed configuration for a specific resource. Params: `resource_type`, `uuid` | No |
| `opn_haproxy_configtest` | Validate HAProxy configuration syntax before applying | No |
| `opn_haproxy_add` | Create a new HAProxy resource. Params: `resource_type`, `config` (dict of field values) | Yes |
| `opn_haproxy_update` | Update an existing HAProxy resource (partial updates). Params: `resource_type`, `uuid`, `config` | Yes |
| `opn_haproxy_delete` | Delete a HAProxy resource by UUID. Params: `resource_type`, `uuid` | Yes |
| `opn_reconfigure_haproxy` | Apply pending HAProxy configuration changes | Yes |

> **Note:** HAProxy changes do NOT use savepoint protection — they apply immediately on reconfigure. Always call `opn_haproxy_configtest` before `opn_reconfigure_haproxy`.

### Services (11 tools)

| Tool | Description | Writes |
| --- | --- | --- |
| `opn_list_acme_certs` | ACME/Let's Encrypt certificates and their status. Params: `search`, `limit` | No |
| `opn_list_cron_jobs` | Scheduled cron jobs. Params: `search`, `limit` | No |
| `opn_crowdsec_status` | CrowdSec security engine status and active decisions | No |
| `opn_crowdsec_alerts` | CrowdSec security alerts (detected threats). Params: `search`, `limit` | No |
| `opn_list_ddns_accounts` | Dynamic DNS accounts and their update status. Params: `search`, `limit` | No |
| `opn_add_ddns_account` | Create a new Dynamic DNS account. Params: `service`, `hostname`, `username`, `password`, `checkip`, `interface`, `description` | Yes |
| `opn_reconfigure_ddclient` | Apply pending Dynamic DNS configuration changes | Yes |
| `opn_update_ddns_account` | Update a Dynamic DNS account (password is write-only). Params: `uuid`, `service`, `hostname`, `username`, `password`, `checkip`, `interface`, `description`, `enabled` | Yes |
| `opn_delete_ddns_account` | Delete a Dynamic DNS account by UUID. Params: `uuid` | Yes |
| `opn_mdns_repeater_status` | mDNS Repeater status and configuration (enabled, interfaces, blocklist). Requires `os-mdns-repeater` plugin | No |
| `opn_configure_mdns_repeater` | Configure mDNS Repeater for cross-VLAN device discovery (HomeKit, Chromecast, AirPlay). Params: `enabled`, `interfaces` | Yes |

### Diagnostics (4 tools)

| Tool | Description |
| --- | --- |
| `opn_ping` | Ping a host from the firewall to test connectivity. Params: `host`, `count` (1-10, default 3) |
| `opn_traceroute` | Trace network path to a destination. Params: `host`, `protocol` (ICMP/UDP/TCP), `ip_version` (4/6) |
| `opn_dns_lookup` | DNS lookup from the firewall. Params: `hostname`, `server` (optional custom DNS server) |
| `opn_pf_states` | Query active PF state table. Params: `search`, `limit` (max 1000) |

### Security (1 tool)

| Tool | Description |
| --- | --- |
| `opn_security_audit` | Comprehensive 11-area security audit: firmware, firewall rules (MVC + legacy, port grouping, insecure protocols), NAT forwarding, DNS security (DNSSEC, DoT), system hardening (SSH, HTTPS, syslog), services, certificates (ACME + system + CAs), VPN (WireGuard config, IPsec, OpenVPN), HAProxy (headers, health checks), gateways. Findings tagged with PCI DSS v4.0, BSI IT-Grundschutz, NIST 800-41, CIS compliance references. |

## Read-only policy and legacy write functions

In **named-target mode**, `OPNSENSE_MCP_READ_ONLY=true` (default) prevents configuration changes on every site. The optional `OPNSENSE_<SITE>_READ_ONLY` setting overrides the global choice for one explicitly named target. For example, `OPNSENSE_LOCAL_READ_ONLY=false` permits write-classified operations *only on `local`* when the global setting is true. The user must deliberately opt into this risk; the MCP bearer token grants access to the entire server and is **not** a per-user authorization mechanism.

The API client explicitly classifies **operations**, not HTTP methods: a read or diagnostic operation can use GET or POST; a potentially mutating/unclassified operation is denied before any network request in read-only mode, even when it uses GET. Read-only classification includes limited diagnostics such as the firmware repository check, which refreshes probe metadata but does not install packages.

The firmware update check (`opn_check_firmware_updates`) is allowed in named-target mode: it refreshes firmware check metadata without installing packages. The actual firmware update and upgrade endpoints remain blocked.

Write tools remain visible in the inherited tool catalog but are **not executable on read-only targets**. If a site is explicitly configured as writable, these tools become callable subject to the absolute endpoint blocklist, target API permissions, and individual tool checks; OPNsense 26.7+ has no automatic firewall rollback. Some state-changing diagnostics (such as job-based ping/traceroute) can also be denied by the central policy, until they have been individually reviewed.

For **legacy single-target stdio only**, the inherited `OPNSENSE_ALLOW_WRITES=true` option still exists. Do not enable this for an AI-connected production firewall. In OPNsense **26.7+**, the older savepoint/60-second rollback API was removed; potentially disruptive changes will not automatically revert.

Over HTTP, `opn_download_config` and `opn_get_config_section` return an error rather than returning arbitrary `config.xml` data. The summarized inventory tool `opn_scan_config` can still read the configuration internally.

## Security model

- **HTTP authentication:** FastMCP checks a mandatory bearer token. Clients knowing that token can potentially query **all** configured sites; individual client/site authorization has not been implemented.
- **Separate VM:** Enforce an **external** egress allowlist allowing only the selected OPNsense API IP/port pairs. Block unrestricted public Internet, other internal hosts, DNS and IPv6 paths. Never trust container-local firewall rules against malicious container code.
- **API least privilege:** Use dedicated OPNsense read-only API accounts with only the permissions required for the selected tools. OPNsense API privileges do not reliably distinguish GET from POST or harmless from mutating operations. The MCP policy adds operation-level control.
- **Output control:** FastMCP caps tool-response size (default 16 KiB); a middleware suppresses structured responses with common secret-shaped keys. These heuristics **do not prove that all secrets are removed**.
- **No direct SSH or shell:** Requests use the OPNsense REST API. The container is configured as non-root, with read-only root filesystem and dropped capabilities.
- **Controlled updates:** Watchtower opt-out; the GHCR publishing workflow must be started manually. Audit dependencies and prefer SHA-tagged images rather than automatic updates.
- **Wire confidentiality:** The supplied HTTP example uses **unencrypted HTTP**, including for the bearer token. Restrict it to a trusted internal network or use TLS when required.

This implementation is **not certified as exfiltration-proof or comprehensively secret-safe**. An external firewall boundary and least-privilege API accounts remain mandatory before using real credentials.

## IPv6 and compatibility notes

The server can inspect IPv6 interface information, NDP, routes, gateway status, VPN state, firewall rules, DNS, DHCP and HAProxy. It does not provide comprehensive native administration of IPv6 prefix delegation, `radvd`, Kea DHCPv6, or the legacy GUI's firewall rule format. Some plugin-specific read tools can expose unexpected fields and require validation before sensitive use.

The upstream server supports OPNsense 24.7+ and automatically chooses camelCase (older API) or snake_case (25.7+) endpoint variants. **This fork has not yet been validated with live OPNsense 26.7+ devices.**

## Troubleshooting

| Symptom | Likely cause / check |
| --- | --- |
| Container exits immediately | Missing/short MCP token, invalid site names or missing URL/key/secret. Check Portainer logs. |
| HTTP 401 from `/mcp` | Missing or incorrect MCP bearer token, **not** an OPNsense API error. |
| TCP connection refused | Wrong VM hostname/port, Docker port mapping, or VM firewall. |
| OPNsense API timeout/401/403 | Check selected `site`, URL/port, TLS, outbound firewall and API privileges. |
| `site is required` | More than one named target exists; supply the site alias in the tool call. |
| Write operation denied | Expected when global or site read-only is true. `OPNSENSE_ALLOW_WRITES` does not control named targets. |
| Raw `config.xml` denied | Expected for HTTP mode. Use inventory and dedicated inspection tools. |
| Tool output suppressed/truncated | A sensitive field name or size limit was encountered; narrow the query or limit. |
| GUI firewall rules not listed | MVC rule search does not necessarily include legacy GUI rules. |

A Docker TCP healthcheck proves only that the listener is reachable, not that OPNsense API calls or secret filtering work.

## Development

```bash
git clone https://github.com/meyergru/opnsense-mcp-server.git
cd opnsense-mcp-server
python -m pip install -e ".[dev]"

pytest -v
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
```

See [multi-target details](docs/multi-target.md), [HTTP/Portainer deployment](docs/http-compose.md) and [CI](.github/workflows/ci.yml). CI builds the Docker image and checks the HTTP authentication handshake with no live firewall connection.

## Upstream and license

This repository originated as a fork of [lucamarien/opnsense-mcp-server](https://github.com/lucamarien/opnsense-mcp-server). Original copyright notices are retained. Licensed under **MIT**; see [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
