# Secret-handling boundaries

**If you do not trust this firewall-management MCP server, do not use it.**
The server is a privileged management component. Secret disclosure cannot be
made impossible while retaining every legitimate provisioning workflow.

## Three distinct cases

1. **Opaque internal transfer** (preferred when supported). For OPNsense-to-OPNsense
   WireGuard PSK changes, `opn_wireguard_generate_psk` creates a random PSK
   in server memory and returns a short-lived `psk_ref`. The same reference
   can be supplied when changing the two OPNsense peers; the PSK itself is not
   returned to the model. WireGuard *private* keys should normally be created
   and retained on their respective devices; *public* keys are intended for exchange.
2. **Deliberate secret input or output**. Some legitimate requests cannot be
   completed without exposing a secret to the agent, its client or a human
   operator. Examples include configuring an OPNsense peer against a FritzBox
   or UniFi device without an integrated management tool, setting a DDNS
   provider password/token, rotating an account password, and generating a new
   API token to hand to the user. Such workflows require explicit authorization
   and careful handling of the secret, but should not be categorically
   prohibited by architectural policy. Where feasible, generate the private
   key on the device that retains it and exchange only the public key.
3. **Incidental secret disclosure** (not intended). Ordinary inventory,
   configuration, lease, audit and status responses should not include
   stored credentials. Configuration exports and section reads redact likely
   secrets by default; unredacted output requires the operator to set
   `OPNSENSE_ALLOW_SENSITIVE=true` and request `include_sensitive=true`.
   HTTP raw `config.xml` export/section reads remain blocked. Malformed XML is
   refused rather than returned unredacted. These are heuristic protections,
   not a proof of redaction.

## What the implementation currently does

- `opn_add_ddns_account` and `opn_update_ddns_account` accept a
  `password` parameter (which can carry a provider password or API token).
  This is **intentional**, inherited functionality. The secret traverses the
  AI/MCP client and the MCP server. It is not an opaque reference and is not
  protected from client-side chat history or logging merely because responses
  are filtered. **No change to DDNS functionality is planned by this document.**
- The WireGuard `psk_ref` mechanism is limited to tools that can consume
  that reference on the server. It does not allow exporting the PSK for manual
  entry into a non-MCP device; such an exchange requires a distinct, deliberate
  workflow rather than silently weakening the output guard.
- There is no dedicated tool for generating an OPNsense API token, exporting a
  WireGuard private key or revealing an individual stored password. In legacy
  stdio mode, however, the configuration tools can expose unredacted config
  data when the operator explicitly enables `OPNSENSE_ALLOW_SENSITIVE=true`
  and the caller requests `include_sensitive=true`. A user request alone does
  not enable that capability.
- The configured HTTP transport can be plain HTTP on a private management
  network. A manually entered secret may be exposed in prompts, provider
  logs, transcripts, network transport and client history. Prefer TLS or
  a trusted protected channel when transporting sensitive values.

## Design rule for future explicit secret workflows

Treat intentional secret delivery as an **operation with a precisely defined
purpose, recipient and output**, not as a global bypass of response sanitization.
Document whether the value is generated, imported, rotated, shown once or
stored; which systems and model context see it; and how it can be revoked.
Prefer public keys, device-local key generation and opaque references when
those satisfy the actual task. If they do not, allow an explicitly authorized
and auditable secret exchange instead of pretending every system has an MCP
integration. Do not conflate an AI agent's ability to request a secret with
permission to retrieve existing secrets without user authorization.
