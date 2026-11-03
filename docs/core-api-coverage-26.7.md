# OPNsense Core 26.7 API coverage: scope and remaining gaps

**Reference:** `opnsense/core` branch `stable/26.7`, directory
`src/opnsense/mvc/app/controllers/OPNsense/*/Api/` (reviewed 2026-11-03).
This is a **source-tree inventory**, NOT a claim that every OPNsense API
endpoint is implemented or safe for a remote AI agent. The 24 areas below
contain **126 API controller classes**; each controller can define multiple
actions and inherit more from MVC base controllers. Therefore the controller
count must not be confused with endpoint count or MCP tool count.

| Core API area | Controllers | MCP coverage (examples / limitations) |
| --- | ---: | --- |
| Auth | 3 | No account/privilege management tools; deliberate sensitive gap |
| CaptivePortal | 6 | Not covered |
| Core | 12 | Firmware, snapshots, service inventory, backup limitations; see detailed matrices |
| Cron | 2 | Read/search only |
| DHCRelay | 2 | Not covered |
| Diagnostics | 17 | Ping, DNS, traceroute, PF states, interface telemetry; others missing |
| Dnsmasq | 3 | Leases, ranges, reconfigure; partial |
| Firewall | 12 | Filter, aliases, categories and some NAT; partial (not all NAT/routing controllers) |
| Hostdiscovery | 2 | Not covered |
| IDS | 2 | Not covered |
| IPsec | 14 | Service status only; configuration/SA/connection controls missing |
| Interfaces | 13 | Status/ARP/NDP; assignment/VLAN/bridge/VIP settings not covered |
| Kea | 8 | DHCPv4 and lease search partial; v6/HA/DDNS/control agent missing |
| Monit | 3 | Not covered |
| Ntpd | 1 | Not covered |
| OpenVPN | 4 | Instance search/status only; no full configuration CRUD |
| Radvd | 2 | Not covered |
| Routes | 2 | Gateway status; incomplete gateway configuration and route controls |
| Routing | 2 | Not covered |
| Syslog | 2 | Not covered |
| TrafficShaper | 2 | Not covered |
| Trust | 4 | Limited certificate inventory, no trust-store management |
| Unbound | 4 | DNS overrides/forwards/stats/DNSBL; partial |
| Wireguard | 4 | Service/peer queries; full configuration management not covered |
| **Total** | **126** | **Partial by design** |

These module names and counts are based on the 26.7 source folder listings.
OPNsense plugins are **not included**: ACME, HAProxy, CrowdSec, DDclient and
other plugins have separate API controllers. Actual plugin sets vary by
firewall. Inventorying them exhaustively requires each target's installed
plugin names/versions (and sometimes its API source code).

## FirmwareController: 26 public actions

The following table is the explicit 26.7 controller-to-MCP reconciliation.
"Exposed" means a reviewed logical endpoint exists, with the noted
read-only policy. It does **not** claim live-device verification.

| OPNsense actions | MCP status | Operation policy / notes |
| --- | --- | --- |
| `status` | Exposed | GET cached READ; POST synchronous DIAGNOSTIC |
| `audit` | **New: exposed** | POST DIAGNOSTIC; original VuXML package/CVE scan, bounded monitor |
| `update` | Exposed | POST WRITE; no-reboot guard and explicit confirm |
| `running` | Exposed | GET READ |
| `upgradestatus` | Exposed | GET READ; **global**, not per-job log |
| `info` | Exposed | GET READ |
| `check` | Not exposed | Async update check; synchronous status probe already available |
| `changelog`, `details`, `license` | Not exposed | Read-like POST with user-supplied identifiers; not yet reviewed for output/sanitization |
| `log` | Not exposed | POST log show/clear; not required for the CVE audit; clear is mutating |
| `health`, `connection` | Not exposed | Other asynchronous diagnostics; candidates for dedicated tools |
| `cleanup` | Not exposed | Potentially mutating; requires explicit review |
| `getOptions` | Not exposed | Read-only firmware settings options; useful candidate |
| `set` | Not exposed | Firmware repository/mirror configuration WRITE (high-risk) |
| `reinstall`, `install`, `remove`, `lock`, `unlock` | Not exposed | Package-changing actions; high-risk |
| `syncPlugins`, `resyncPlugins` | Not exposed | State-changing plugin operations |
| `upgrade` | **Blocked** | Major version upgrade: unconditional blocklist |
| `reboot`, `poweroff` | **Blocked** | Unconditional blocklist |

Two API methods absent from the public-action list may be inherited via base
controller paths. This table deliberately counts only methods actually
declared in the controller source.

## SnapshotsController: 7 actions

| Action | MCP status | Notes |
| --- | --- | --- |
| `isSupported`, `search`, `get` | Exposed | Read-only |
| `add` | Exposed | WRITE; creates boot environment without activation |
| `set`, `del`, `activate` | Not exposed | Changes metadata or boot environment; requires rollback and safety design |

## Firmware CVE audit: implementation and evidence limits

`opn_firmware_cve_audit` starts the **original** OPNsense firmware audit
(`POST /api/core/firmware/audit`), which checks installed packages against
known VuXML vulnerabilities. On first call it checks backend idleness and
captures the existing global firmware progress log, then starts a new scan and
polls briefly. If still running, call `opn_firmware_cve_audit_result` with
the returned job ID. Both are allowed under `OPNSENSE_MCP_READ_ONLY=true`;
the backend writes temporary scan logs but neither installs packages nor
reboots.

The OPNsense API returns a `msg_uuid` when the job is started, but its
`GET /api/core/firmware/upgradestatus` has **no per-UUID read endpoint**.
To avoid stale, false-clean reports, this MCP server requires a *changed*
backend log with the audit-specific marker and `***DONE***`. A structured
`clean` finding additionally requires the explicit
`0 problem(s) in 0 installed package(s) found` output. Absence of parsed
CVEs alone is **never** reported as clean. Scan results are unavailable if
the container restarts before the monitor can correlate the log.

Even fresh-log correlation cannot prove job identity against simultaneous
out-of-band firmware activity (for example, an administrator initiating an
audit from the GUI). The tool reports this limitation explicitly. These
checks are based on source/fixtures; real OPNsense responses may differ.

## Automated vs. unverified scope

- **Automated:** every MCP tool's known logical endpoint is classified; every
  classified endpoint is resolvable (except audited dynamic HAProxy CRUD
  names); unknown endpoints fail closed for both writable and read-only sites.
- **Source-reviewed:** the Core 26.7 firmware and snapshot controller actions
  and their HTTP effects.
- **Not automatically covered:** unimplemented controllers, plugin-specific
  functions, undocumented inherited routes, newly released API methods, or
  version-specific differences in deployed OPNsense installations.

Adding an API endpoint is a deliberate security and product decision.
A generic unaudited `call_any_api` endpoint would defeat this model.

Sources: [OPNsense Core (stable/26.7)](https://github.com/opnsense/core/tree/stable/26.7/src/opnsense/mvc/app/controllers/OPNsense),
[OPNsense Firmware API](https://docs.opnsense.org/development/api/core/firmware.html),
[OPNsense Security](https://docs.opnsense.org/security.html).
