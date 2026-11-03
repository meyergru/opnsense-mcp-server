# OPNsense API operation inventory and authorization policy

This file describes the audited **scope of this MCP server**, not an
exhaustive catalogue of every endpoint exposed by OPNsense, all its plugins,
or future releases.

## Coverage

- **106** static logical endpoints in `ENDPOINT_REGISTRY`.
- **36** dynamically constructed HAProxy resource endpoints (nine resource
  kinds × get/add/set/del), with validated resource identifiers.
- Some logical endpoints have **multiple differently classified HTTP
  operations** (e.g. GET vs POST `core/firmware/status`).
- **83 MCP tools** are a separate count: a single tool may call several
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
| POST `firmware.status` | DIAGNOSTIC | Refresh update metadata via `firmware probe`, without package installation |
| GET `haproxy.service.configtest` | DIAGNOSTIC | Run a syntax check, not activate a config |
| POST `diagnostics.ping.set/start/remove` | WRITE | Creates/starts/removes temporary jobs and sends network probes |
| POST `diagnostics.traceroute.set` | WRITE | Initiates outgoing network probes |
| POST `diagnostics.dns_diagnostics.set` | WRITE | Sends DNS requests from the firewall |
| GET `core.backup.download` | READ | Sensitive export risk: raw backup is **blocked for HTTP MCP clients** despite being non-mutating |

The diagnostic networking operations are deliberately disabled on read-only
sites until their destination and operational risks have been assessed. No
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

See the [official OPNsense API reference](https://docs.opnsense.org/development/api.html),
which covers many additional core and plugin modules and explains that its
documentation is auto-generated from available endpoints.
