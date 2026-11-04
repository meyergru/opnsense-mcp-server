# OPNsense Core 26.7 API coverage: scope and remaining gaps

**Reference:** `opnsense/core` branch `stable/26.7`, directory
`src/opnsense/mvc/app/controllers/OPNsense/*/Api/` (initially reviewed 2026-11-03; coverage reconciled with PR #12 on 2026-11-04).
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
| Firewall | 12 | Filter, alias, category and DNAT operations exposed, but **Source NAT, 1:1 NAT, NPTv6**, groups and numerous utilities are not fully exposed; see controller audit below |
| Hostdiscovery | 2 | Not covered |
| IDS | 2 | Not covered |
| IPsec | 14 | Service status only; configuration/SA/connection controls missing |
| Interfaces | 13 | Status/ARP/NDP; assignment/VLAN/bridge/VIP settings not covered |
| Kea | 8 | **Expanded:** DHCPv4/v6 subnet/reservation/option/HA-peer/PD-pool object operations, global settings and v6 lease queries; other controller actions and live validation remain open |
| Monit | 3 | Not covered |
| Ntpd | 1 | Not covered |
| OpenVPN | 4 | Instance search/status only; no full configuration CRUD |
| Radvd | 2 | **Expanded:** entry CRUD, toggle, global settings and explicit service apply; other actions remain subject to verification |
| Routes | 2 | Gateway status; incomplete gateway configuration and route controls |
| Routing | 2 | Not covered |
| Syslog | 2 | Not covered |
| TrafficShaper | 2 | Not covered |
| Trust | 4 | Limited certificate inventory, no trust-store management |
| Unbound | 4 | **Expanded:** host/alias/forward/ACL/DNSBL CRUD and toggle, global settings and apply; diagnostics/overview and special endpoints remain partial |
| Wireguard | 4 | **Expanded:** peer and instance CRUD, explicit enable/disable, opaque PSK reference, general settings, service apply; special builder/diagnostic actions and live validation remain open |
| **Total** | **126** | **Partial by design** |

These module names and counts are based on the 26.7 source folder listings.
OPNsense plugins are **not included**: ACME, HAProxy, CrowdSec, DDclient and
other plugins have separate API controllers. Actual plugin sets vary by
firewall. Inventorying them exhaustively requires each target's installed
plugin names/versions (and sometimes its API source code).

## Implemented tool surface versus API completeness

As of PR #12 on 2026-11-04, the MCP server registers **129 tools**,
including **35 single-site MVC tools** for Kea, radvd, Unbound and WireGuard.
Counts of tools are not counts of OPNsense API actions: one tool may cover
several reviewed object kinds; conversely, one resource may require separate
get/search/set/add/delete/toggle operations.

The finite `mvc_catalog.py` generates the logical paths for the four
families. The `api_client.py` registry controls classification and
authorization. These checks establish the **implemented** surface, not
full coverage of every Core controller, every inherited MVC action, or
every installed plugin's API.

An inventory that calls a module "covered" means only that the listed
operations are mapped and tested against source/fixtures. **There has
been no exhaustive live test of all CRUD paths against an OPNsense 26.7
installation.** The module-level status remains partial until each action
has been reconciled with its controller and verified.

## Firewall API controller reconciliation (Core stable/26.7)

All twelve controller classes in
`OPNsense/Firewall/Api/` were enumerated from `stable/26.7`.
The actions shown below are actions **declared in those classes**; inherited
MVC actions and plugin-specific APIs are additional scope. The "MCP" column
describes the current 21 Firewall MCP tools, not a comprehensive wrapper.

| Controller | Declared API actions in OPNsense 26.7 | Present MCP coverage and outstanding gaps |
| --- | --- | --- |
| `Alias` | searchItem, listCategories, setItem, addItem, getItem, getAliasUUID, delItem, toggleItem, listCountries, listUserGroups, listNetworkAliases, reconfigure, getTableSize, export, import, getGeoIP, update | Search/get/add/set/delete/toggle exposed; utility/list/export/import/update operations only partially or not covered |
| `AliasUtil` | aliases, list, flush, delete, add, findReferences | **Not fully exposed**; important prerequisite for dependency-aware alias deletion |
| `Category` | searchItem, setItem, addItem, getItem, delItem, download, upload | Search/add/delete and category assignments exposed; get/set/download/upload remain incomplete |
| `DNat` | searchRule, setRule, addRule, getRule, delRule, toggleRule, moveRuleBefore, toggleRuleLog, downloadRules, uploadRules | Search/add/set/delete exposed; get/toggle/move/log/import/export incomplete |
| `FilterBase` | listCategories, listNetworkSelectOptions, listPortSelectOptions, apply | Apply/savepoint used by existing tools; selection helpers incomplete; inherited by Filter/NAT controllers |
| `Filter` | searchRule, setRule, addRule, getRule, delRule, toggleRule, toggleRuleLog, moveRuleBefore, getInterfaceList, downloadRules, uploadRules, flushInspectCache | Search/add/set/delete/toggle exposed; get, log toggle, ordering, import/export and cache utilities incomplete |
| `FilterUtil` | ruleStats | **Not exposed** as dedicated tool |
| `Group` | searchItem, setItem, addItem, getItem, delItem, reconfigure | **Not covered** for firewall interface groups |
| `Migration` | downloadRules, countRules, flush, downloadOutbound, countOutbound, flushOutbound | **Not covered**; destructive migration/flush operations require separate authorization review |
| `Npt` | searchRule, setRule, addRule, getRule, delRule, toggleRule, moveRuleBefore, toggleRuleLog, downloadRules, uploadRules | **Not covered** (NPTv6) |
| `OneToOne` | searchRule, setRule, addRule, getRule, delRule, toggleRule, moveRuleBefore, toggleRuleLog, downloadRules, uploadRules | **Not covered** (1:1 NAT) |
| `SourceNat` | set, get, searchRule, setRule, addRule, getRule, delRule, toggleRule, moveRuleBefore, toggleRuleLog, downloadRules, uploadRules | **Not covered** (outbound/source NAT and mode configuration) |

**Firewall implementation priorities:** (1) single-object get/search and
idempotent toggle for Filter, DNAT, Source NAT, 1:1 NAT and NPTv6;
(2) add/patch/delete using read-before-write and explicit per-site write
control; (3) rule order and log toggles; (4) alias-reference checks,
interface groups, and selection utilities; (5) import/export and
destructive migration operations only after separate review.

As with Kea/WireGuard, **cross-site dependencies and ordering belong
to the model**. The MCP server enforces only per-site authorization,
validated fields, one-object changes, and explicit apply. A firewall
rule apply can interrupt management access, so rollback semantics must
be checked for each OPNsense version before exposure.

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
