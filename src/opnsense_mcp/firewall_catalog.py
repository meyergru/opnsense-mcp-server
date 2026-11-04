"""Fixed OPNsense 26.7 Firewall controller catalogue.

Each logical API operation names a known controller and method.
No caller can supply an arbitrary URL. Legacy/non-MVC rules can appear in
search results but cannot be mutated via these MVC CRUD endpoints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class FirewallResource:
    controller: str
    field: str
    actions: str = "Rule"
    movable: bool = False
    logging: bool = False
    toggle: bool = False
    inverted_toggle: bool = False


FirewallResourceName = Literal["filter", "dnat", "snat", "one_to_one", "npt", "alias", "category", "group"]
FirewallToggleKind = Literal["filter", "dnat", "snat", "one_to_one", "npt", "alias"]
FirewallLoggingKind = Literal["filter", "dnat", "snat", "one_to_one", "npt"]
FirewallMoveKind = Literal["filter", "dnat", "snat", "one_to_one", "npt"]


RESOURCES: dict[str, FirewallResource] = {
    "filter": FirewallResource("filter", "rule", movable=True, logging=True, toggle=True),
    "dnat": FirewallResource("d_nat", "rule", movable=True, logging=True, toggle=True, inverted_toggle=True),
    "snat": FirewallResource("source_nat", "rule", movable=True, logging=True, toggle=True),
    "one_to_one": FirewallResource("one_to_one", "rule", movable=True, logging=True, toggle=True),
    "npt": FirewallResource("npt", "rule", movable=True, logging=True, toggle=True),
    "alias": FirewallResource("alias", "alias", "Item", toggle=True),
    "category": FirewallResource("category", "category", "Item"),
    "group": FirewallResource("group", "group", "Item"),
}


def _snake(action: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", action).lower()


def generate_operations() -> tuple[
    dict[str, tuple[str, str]], frozenset[str], frozenset[str], frozenset[tuple[str, str]]
]:
    endpoints: dict[str, tuple[str, str]] = {}
    read_get: set[str] = set()
    read_post: set[str] = set()
    write_post: set[tuple[str, str]] = set()

    def register(key: str, controller: str, action: str, method: str, read: bool) -> None:
        endpoints[key] = (
            f"firewall/{controller}/{action}",
            f"firewall/{controller}/{_snake(action)}",
        )
        if read and method == "GET":
            read_get.add(key)
        elif read and method == "POST":
            read_post.add(key)
        elif method == "POST":
            write_post.add(("POST", key))
        else:
            raise ValueError(f"Unreviewed Firewall operation: {key}")

    for kind, resource in RESOURCES.items():
        for verb, method, read in (
            ("search", "POST", True),
            ("get", "GET", True),
            ("add", "POST", False),
            ("set", "POST", False),
            ("del", "POST", False),
        ):
            register(
                f"fw26.{kind}.{verb}",
                resource.controller,
                f"{verb}{resource.actions}",
                method,
                read,
            )
        if resource.toggle:
            register(f"fw26.{kind}.toggle", resource.controller, f"toggle{resource.actions}", "POST", False)
        if resource.movable:
            register(f"fw26.{kind}.move", resource.controller, "moveRuleBefore", "POST", False)
        if resource.logging:
            register(f"fw26.{kind}.log", resource.controller, "toggleRuleLog", "POST", False)

    # Controller-specific non-CRUD calls, also explicitly reviewed.
    for key, controller, action in (
        ("fw26.source_nat.get_settings", "source_nat", "get"),
        ("fw26.filter.get_interfaces", "filter", "getInterfaceList"),
        ("fw26.filter.rule_stats", "filter_util", "ruleStats"),
        ("fw26.alias.references", "alias_util", "findReferences"),
        ("fw26.alias.table_size", "alias", "getTableSize"),
        ("fw26.alias.list_tables", "alias_util", "aliases"),
        ("fw26.alias.table_contents", "alias_util", "list"),
        ("fw26.migration.count_rules", "migration", "countRules"),
        ("fw26.migration.count_outbound", "migration", "countOutbound"),
    ):
        method = "POST" if key == "fw26.alias.references" else "GET"
        register(key, controller, action, method, True)

    for key, controller, action in (
        ("fw26.source_nat.set_settings", "source_nat", "set"),
        ("fw26.filter.apply", "filter", "apply"),
        ("fw26.alias.reconfigure", "alias", "reconfigure"),
        ("fw26.group.reconfigure", "group", "reconfigure"),
    ):
        register(key, controller, action, "POST", False)

    return endpoints, frozenset(read_get), frozenset(read_post), frozenset(write_post)


FIREWALL_ENDPOINTS, FIREWALL_GETS, FIREWALL_SEARCHES, FIREWALL_WRITES = generate_operations()
