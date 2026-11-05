# Secrets, credentials and manual hand-off

> [!CAUTION]
> **If you do not trust this MCP server and the AI clients using it, do not
> connect it to your firewalls.** These controls avoid accidental disclosures;
> they do not establish a security boundary against a fully compromised server
> or agent.

## Choose the smallest necessary exposure

Not all key material is secret, and not all secret transfers are avoidable.

| Material / request | Intended workflow |
| --- | --- |
| WireGuard public keys, public certificates, CSRs | Return and exchange normally; they are public material. |
| WireGuard private keys | Generate and retain each key on its owning device whenever possible; only exchange its public key. |
| WireGuard preshared keys (PSKs) between MCP-managed OPNsense sites | Generate once using `opn_wireguard_generate_psk`; use the same 30-minute opaque `psk_ref` on both peers, without returning the PSK to the AI. |
| WireGuard PSK shared with an unmanaged Fritzbox/UniFi/other endpoint | An opaque reference on the OPNsense MCP server cannot be consumed by the unmanaged endpoint. Arrange an explicit, trusted manual hand-off or a separately authorized one-time export/import mechanism. |
| DDNS provider password/API token | `opn_add_ddns_account` and `opn_update_ddns_account` currently accept `password` and `username` as ordinary tool arguments. The value is visible to the invoking AI client/tool invocation before it is sent to OPNsense. This is **intentional current behavior**, not an opaque-secret API. |
| Set a service password or API token | A future tool may accept a new secret supplied by the authorized user or another trusted component. Such operations must explicitly disclose where the secret travels and whether it is stored or returned. |
| Generate a token and show it to the user | A legitimate *explicitly requested* capability, but a one-time plaintext response exposes the token to the AI client, conversation history and possibly logs. This capability is **not** provided merely by the current OPNsense tool catalog; it would require a reviewed, explicit tool. |
| Retrieve an existing password, private key or API token | Do not infer permission from configuration-read access. Any intentional retrieval needs a purpose-built, explicitly authorized operation and clear disclosure of the exposure path. |

**WireGuard without an MCP-managed second device:** An asymmetric WireGuard
connection normally needs each side's *public* key, not the export of either
side's private key. Both endpoints can generate their own keypairs locally;
exchange public keys and configure AllowedIPs/endpoints. A separate PSK is
optional but, when used, must be identical on both sides. Some products or
migration flows impose additional constraints; confirm the actual device API
before deciding a private-key hand-off is necessary.

## Current behavior and limitations

- The server currently strips a set of secret-shaped keys from many MVC
  responses and suppresses structured MCP results containing recognized
  secret-shaped fields. This is a defensive heuristic, not a guarantee.
- Its generic secret-output guard is *not* a deliberate token-export mechanism.
  A future explicit one-time export would need reviewed, purpose-specific
  handling rather than a blanket exception to secret filtering.
- The DDNS create/update tools pass provider credentials directly to the OPNsense
  API, and must not echo them into regular tool results. Do not paste secrets into
  ordinary model prompts unless you accept exposure within that AI environment.
- Read-only MCP credentials and fixed targets do not make a malicious AI
  instruction safe. Consider the model and all connected tools together.
- Be explicit about the trust boundary: *generated on a firewall*, *processed in
  the MCP server*, *passed through the AI client*, and *displayed to the user*
  are different levels of exposure. An opaque reference only solves transfers
  between components capable of resolving that same reference.
- For a managed-to-unmanaged device pair, a human-entered value or an external
  audited secret delivery mechanism may be necessary; do not pretend an
  inaccessible device can use an internal MCP reference.

This section documents existing behavior and design principles. It does **not**
enable new secret-reading, token-generation, private-key export, or password
administration operations.
