"""Audited MVC resource catalogue (no dynamic arbitrary-endpoint passthrough).

Each entry is a known OPNsense Core 26.7 controller/action family. The
logical endpoint registry and method classification derive from this fixed
catalogue, not from model-supplied URL paths.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MVCResource:
    family: str
    controller: str
    action: str
    field: str
    toggle: bool = False
    kind: str = ""

    def logical(self, verb: str) -> str:
        return f"mvc.{self.family}.{self.kind or self.action.lower()}.{verb}"


RESOURCES: dict[str, dict[str, MVCResource]] = {
    "wireguard": {
        "peer": MVCResource("wireguard", "wireguard/client", "Client", "client", True),
        "instance": MVCResource("wireguard", "wireguard/server", "Server", "server", True),
    },
    "radvd": {
        "entry": MVCResource("radvd", "radvd/settings", "Entry", "entries", True),
    },
    "kea": {
        "subnet4": MVCResource("kea", "kea/dhcpv4", "Subnet", "subnet4"),
        "reservation4": MVCResource("kea", "kea/dhcpv4", "Reservation", "reservation"),
        "option4": MVCResource("kea", "kea/dhcpv4", "Option", "option"),
        "ha_peer4": MVCResource("kea", "kea/dhcpv4", "Peer", "peer"),
        "subnet6": MVCResource("kea", "kea/dhcpv6", "Subnet", "subnet6"),
        "reservation6": MVCResource("kea", "kea/dhcpv6", "Reservation", "reservation"),
        "option6": MVCResource("kea", "kea/dhcpv6", "Option", "option"),
        "pd_pool6": MVCResource("kea", "kea/dhcpv6", "PdPool", "pd_pool"),
        "ha_peer6": MVCResource("kea", "kea/dhcpv6", "Peer", "peer"),
    },
    "unbound": {
        "host": MVCResource("unbound", "unbound/settings", "HostOverride", "host", True),
        "forward": MVCResource("unbound", "unbound/settings", "Forward", "dot", True),
        "host_alias": MVCResource("unbound", "unbound/settings", "HostAlias", "alias", True),
        "acl": MVCResource("unbound", "unbound/settings", "Acl", "acl", True),
        "dnsbl": MVCResource("unbound", "unbound/settings", "Dnsbl", "blocklist", True),
    },
}


def _snake(action: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", action).lower()


# Global configurations use MVC getAction/setAction (partial setNodes on OPNsense).
GLOBAL_SETTINGS: dict[str, tuple[str, str]] = {
    "kea_dhcpv4": ("kea/dhcpv4", "dhcpv4"),
    "kea_dhcpv6": ("kea/dhcpv6", "dhcpv6"),
    "kea_ctrl_agent": ("kea/ctrlAgent", "ctrlagent"),
    "kea_ddns": ("kea/ddns", "ddns"),
    "radvd": ("radvd/settings", "radvd"),
    "unbound": ("unbound/settings", "unbound"),
    "wireguard": ("wireguard/general", "general"),
}

APPLY_SERVICES = frozenset({"kea", "radvd", "unbound", "wireguard"})


def generate_operations() -> tuple[dict[str, tuple[str, str]], frozenset[str], frozenset[str], frozenset[tuple[str, str]]]:
    """Return fixed registry and explicit HTTP-method permissions for these resources."""
    endpoints: dict[str, tuple[str, str]] = {}
    gets: set[str] = set()
    searches: set[str] = set()
    writes: set[tuple[str, str]] = set()
    for name, (controller, _) in GLOBAL_SETTINGS.items():
        for verb in ("get", "set"):
            key = f"mvc.settings.{name}.{verb}"
            endpoints[key] = (f"{controller}/{verb}", f"{controller}/{verb}")
            if verb == "get":
                gets.add(key)
            else:
                writes.add(("POST", key))
    for service in APPLY_SERVICES:
        key = f"mvc.service.{service}.reconfigure"
        path = f"{service}/service/reconfigure"
        endpoints[key] = (path, path)
        writes.add(("POST", key))
    endpoints["mvc.wireguard.instance.generate_keypair"] = (
        "wireguard/server/keyPair", "wireguard/server/key_pair"
    )
    gets.add("mvc.wireguard.instance.generate_keypair")
    endpoints["mvc.kea.leases6.search"] = ("kea/leases6/search", "kea/leases6/search")
    searches.add("mvc.kea.leases6.search")
    endpoints["mvc.kea.leases.del"] = ("kea/leases/delLease", "kea/leases/del_lease")
    writes.add(("POST", "mvc.kea.leases.del"))
    for resources in RESOURCES.values():
        for kind, resource in resources.items():
            for verb in ("search", "get", "add", "set", "del", "toggle"):
                if verb == "toggle" and not resource.toggle:
                    continue
                method = f"{verb}{resource.action}"
                logical = f"mvc.{resource.family}.{kind}.{verb}"
                endpoints[logical] = (f"{resource.controller}/{method}", f"{resource.controller}/{_snake(method)}")
                if verb == "get":
                    gets.add(logical)
                elif verb == "search":
                    searches.add(logical)
                else:
                    writes.add(("POST", logical))
    return endpoints, frozenset(gets), frozenset(searches), frozenset(writes)


MVC_ENDPOINTS, MVC_GETS, MVC_SEARCHES, MVC_WRITES = generate_operations()
