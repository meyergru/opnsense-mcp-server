# os-ddclient (DynDNS) API coverage: OPNsense 26.7

Source-reviewed against:
- [AccountsController.php](https://github.com/opnsense/plugins/blob/stable/26.7/dns/ddclient/src/opnsense/mvc/app/controllers/OPNsense/DynDNS/Api/AccountsController.php)
- [SettingsController.php](https://github.com/opnsense/plugins/blob/stable/26.7/dns/ddclient/src/opnsense/mvc/app/controllers/OPNsense/DynDNS/Api/SettingsController.php)
- [ServiceController.php](https://github.com/opnsense/plugins/blob/stable/26.7/dns/ddclient/src/opnsense/mvc/app/controllers/OPNsense/DynDNS/Api/ServiceController.php)
- [DynDNS.xml model](https://github.com/opnsense/plugins/blob/stable/26.7/dns/ddclient/src/opnsense/mvc/app/models/OPNsense/DynDNS/DynDNS.xml)

This is a source/API inventory, **not a live-firewall verification**.
Requires installed os-ddclient plugin. The plugin supports both the classic
ddclient backend and native Python backend (model value: opnsense).

## Controller action coverage

| Controller action | MCP tool | Effect |
| --- | --- | --- |
| Accounts search_item | opn_list_ddns_accounts | READ (POST search) |
| Accounts get_item | opn_get_ddns_account | READ |
| Accounts add_item | opn_add_ddns_account | WRITE, staged |
| Accounts set_item | opn_update_ddns_account | WRITE, staged |
| Accounts del_item | opn_delete_ddns_account | WRITE, staged |
| Accounts toggle_item | opn_set_ddns_account_enabled | WRITE, idempotent staged |
| Accounts force_refresh | opn_force_refresh_ddns_accounts | WRITE, explicit confirm; native only; internally stops/starts |
| Accounts get | **Omitted intentionally** | Bulk model exposure can reveal credentials |
| Accounts set | **Omitted intentionally** | Broad model update unnecessary; prefer object-scoped changes |
| Settings get | opn_get_ddns_settings | READ, allowlisted fields |
| Settings set | opn_patch_ddns_settings | WRITE, staged |
| Service status | opn_ddns_service_status | READ |
| Service reconfigure | opn_reconfigure_ddclient | WRITE, explicit confirm |
| Service restart | opn_ddns_service_control(action=restart) | WRITE, explicit confirm |
| Service start | opn_ddns_service_control(action=start) | WRITE, explicit confirm |
| Service stop | opn_ddns_service_control(action=stop) | WRITE, explicit confirm |

## Model and security

- The account field is **hostnames**, plural. The MCP's historical input
  argument hostname remains for compatibility but maps to hostnames.
- Password is an UpdateOnlyTextField. Neither list/get nor write response
  contains a password or token; model fields are explicitly allowlisted.
  The caller may set or rotate it, but cannot retrieve its previous value.
- General field names: enabled, verbose, allowipv6, daemon_delay (1..86400),
  backend (ddclient or opnsense). Setting allowipv6 by itself does not force
  AAAA updates; each account needs an IPv6-capable checkip method too.
- Account model options in stable/26.7 include cloudflare, noip,
  he-net, duckdns and custom. IPv6 checkip values include
  web_cloudflare_ipv6 and web_ipify_ipv6; consult the live plugin
  form/model before changing a provider or method.
- Account CRUD and global settings updates are **staged**. Separate
  reconfigure is explicit with confirm=true. Force refresh is different:
  it resets per-account state and restarts the native service, and may
  immediately change externally published DNS records.
- All operations honor the per-site/global write policy and the explicit
  method+endpoint registry. No arbitrary URL or bulk operation is exposed.
- A concurrent GUI write may race an update. The MCP uses the native
  partial setItem API rather than reading back or echoing credentials.
- No live OPNsense calls were made to validate response shapes, plugin
  version differences or backend behavior. Keep read-only until verified.
