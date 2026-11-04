# OPNsense API operation inventory and authorization policy

This file describes the audited **scope of this MCP server**, not an
exhaustive catalogue of every endpoint exposed by OPNsense, all its plugins,
or future releases.

## Coverage

- **297** registered logical endpoints in `ENDPOINT_REGISTRY`: 114 original/static mappings, 114 generated reviewed MVC mappings for Kea/radvd/Unbound/WireGuard, and 69 generated reviewed Firewall 26.7 mappings.
- **36** dynamically constructed HAProxy resource endpoints (nine resource
  kinds × get/add/set/del), with validated resource identifiers.
- Some logical endpoints have **multiple differently classified HTTP
  operations** (e.g. GET vs POST `core/firmware/status`).
- **147 MCP tools** are a separate count: a single tool may call several
  API operations, and a single operation may serve multiple tools.

The current policy is defined in `api_client.py`:

| Class | Definition | Enabled on read-only sites? |
| --- | --- | --- |
| `READ` | Reviewed read/search operation, keyed by method + logical endpoint | Yes |
| `DIAGNOSTIC` | Reviewed bounded diagnostic/check, possibly with ephemeral side effects | Yes |
| `WRITE` | Explicitly reviewed state/configuration-changing operation | No |
| Unclassified | No matching entry in any reviewed list | **No, even on writable sites** |

All three public API accessors (`get`, `post`, `get_text`) enforce this
policy before performing HTTP I/O. Blocking is independent of whether
the API uses GET or POST. Dangerous endpoints on the unconditional blocklist
remain prohibited regardless of the site's write setting.

Named site permissions are controlled via Compose:

```yaml
OPNSENSE_MCP_READ_ONLY: "true"
# OPNSENSE_LOCAL_READ_ONLY: "false"  # optional explicit override for local
```

The default is read-only. Choosing `false` allows the **listed** WRITE
operations for that site; unknown operations are never automatically allowed.

## Ambiguous or special operations requiring explicit review

| Operation | Current class | Reason |
| --- | --- | --- |
| GET `firmware.status` | READ | Read last check result |
| GET `firmware.running`, `firmware.upgradestatus` | READ | Read backend execution state and log; neither confirms a specific job ID |
| GET `snapshots.is_supported`, `snapshots.search`, `snapshots.get` | READ | Check availability, list or inspect ZFS boot environments |
| POST `snapshots.add` | WRITE | Create a new boot-environment snapshot without activating it |
| POST `firmware.update` | WRITE | Start minor/package update asynchronously; limited by confirmation and explicit no-reboot check |
| POST `firmware.status` | DIAGNOSTIC | Refresh update metadata via `firmware probe`, without package installation |
| GET `haproxy.service.configtest` | DIAGNOSTIC | Run a syntax check, not activate a config |
| POST `diagnostics.ping.set/start/remove` | DIAGNOSTIC | Creates/starts/removes temporary jobs and sends network probes; explicitly allowed in read-only mode |
| POST `diagnostics.traceroute.set` | WRITE | Initiates outgoing network probes |
| POST `diagnostics.dns_diagnostics.set` | DIAGNOSTIC | Sends DNS queries from the firewall; explicitly allowed in read-only mode |
| GET `core.backup.download` | READ | Sensitive export risk: raw backup is **blocked for HTTP MCP clients** despite being non-mutating |

Firewall controller-specific details, including the inverse DNAT
toggle semantics and omitted destructive migration actions, are documented
in [Core API coverage](core-api-coverage-26.7.md).

These selected network diagnostics are intentionally allowed on read-only sites;
they can send traffic to user-specified destinations. Traceroute remains
classified as WRITE and blocked on read-only sites pending separate review. No
claim is made that `READ` results are automatically free of passwords,
keys or other sensitive information: output filtering and OPNsense API
privileges are separate security controls.

## Regression coverage and limitations

`tests/test_operation_catalog.py` checks that every statically registered
logical endpoint has at least one reviewed classification; that classes
do not overlap; that all generated HAProxy operations are classified; and
that literal tool API calls and the security-audit pagination calls are
covered. Unknown GET/POST operations are denied **even on writable sites**.
Tests also flag direct tool access to low-level HTTP transport internals.

This guards against accidental policy gaps in the current source tree.
It is **not** an automated semantic proof of safety, nor does it enumerate
APIs not implemented by this MCP server. New OPNsense core/plugin endpoints
require separate implementation, verification against their versioned
controller actions, and a deliberate entry in the operation catalogue.

## Monitoring and transient outages

`opn_monitor_firmware_update` is intentionally a **bounded polling helper**,
not a full update workflow. It performs at most three progress checks and
returns quickly with a status that can be polled again. A temporary TCP/API
outage while the firewall restarts is not treated as a definitive update error.
Successful reconnection is not proof that packages were updated.

The OPNsense backend's `upgradestatus` endpoint exposes a global progress log,
not a job-ID-addressable status endpoint. Even a `***DONE***` marker is
reported as `backend_done`, not as confirmation that a *specific* requested
job completed. Use the product version and subsequent update check as
separate verification; this is still not a guarantee against service restarts.

See the [official OPNsense API reference](https://docs.opnsense.org/development/api.html),
which covers many additional core and plugin modules and explains that its
documentation is auto-generated from available endpoints.
