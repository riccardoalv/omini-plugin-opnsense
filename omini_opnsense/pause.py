"""Pausing a device's internet, over IPv4 and IPv6.

The MAC alias omini_paused_mac holds the paused devices' MACs; OPNsense
resolves it to each device's IPv4 and IPv6 addresses from its ARP and NDP
tables, so a new temporary IPv6 address is covered without Omini knowing it.
Its description keeps which addresses and name each MAC had when paused. One
block rule per LAN-side interface (IPv4+IPv6) stops them from reaching
anything that is not in omini_local: the private IPv4 ranges, IPv6
link-local, ULA and multicast, and the LAN-side interfaces' own IPv6
networks. pause.set and pause.delete change them; collect reports
Device.paused.

Before 0.5.1 the pause was an IPv4 host alias (omini_paused) with IPv4 rules;
the next pause or resume moves its devices to the MAC alias and removes it."""

from __future__ import annotations

import contextlib
import ipaddress
import re
from typing import Any

from omini_sdk import PluginError

from omini_opnsense import networks as nets
from omini_opnsense.client import Client, Forbidden, NotFound
from omini_opnsense.networks import (
    ALIASES,
    LEGACY_PAUSED_ALIAS,
    PAUSED_ALIAS,
    PAUSED_ALIASES,
    PRIVATE_RANGES,
    RULE_PREFIX,
    RULES,
    rows,
    text,
)

DESCRIPTION = "Omini paused:"
RULE_DESCRIPTION = f"{RULE_PREFIX}paused devices (no internet)"
ENTRY = re.compile(r"^([0-9a-f]{2}(?::[0-9a-f]{2}){5})((?: [0-9.]+)*)(?: \((.*)\))?$")

# What a paused device still reaches: its own networks, IPv4 and IPv6.
LOCAL_ALIAS = "omini_local"
LOCAL_IPV6 = ("fe80::/10", "fc00::/7", "ff00::/8")  # link-local, ULA, multicast


def clean_name(name: Any) -> str:
    """A name the description can carry: no separators of its own."""
    return " ".join(re.sub(r"[;()]+", " ", str(name or "")).split())


def describe(paused: list[dict[str, Any]]) -> str:
    """'Omini paused: aa:bb:..:ff 192.168.1.20 (TV); ...'."""
    parts = []
    for p in sorted(paused, key=lambda p: p["mac"]):
        part = " ".join([p["mac"], *p["ips"]])
        if p.get("name"):
            part += f" ({p['name']})"
        parts.append(part)
    return f"{DESCRIPTION} " + "; ".join(parts)


def parse(description: str) -> list[dict[str, Any]]:
    d = description.strip()
    if not d.startswith(DESCRIPTION):
        return []
    out = []
    for part in d[len(DESCRIPTION) :].split(";"):
        m = ENTRY.match(part.strip())
        if m:
            out.append({"mac": m.group(1), "ips": m.group(2).split(), "name": m.group(3) or None})
    return out


def entries(content: Any) -> set[str]:
    """An alias's content as a set (OPNsense lists it by lines or commas)."""
    return {e.lower() for e in re.split(r"[\s,]+", text(content)) if e}


def aliases(c: Client) -> dict[str, dict[str, Any]]:
    """Omini's pause aliases by name: the MAC one, the old IPv4 one, the local one."""
    wanted = (*PAUSED_ALIASES, LOCAL_ALIAS)
    return {
        text(a.get("name")): a
        for a in rows(c, f"{ALIASES}/search_item")
        if text(a.get("name")) in wanted
    }


def items_of(found: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """The paused devices both aliases describe; the MAC alias wins."""
    out: dict[str, dict[str, Any]] = {}
    for name in (LEGACY_PAUSED_ALIAS, PAUSED_ALIAS):
        if name in found:
            for p in parse(text(found[name].get("description"))):
                out[p["mac"]] = p
    return [out[m] for m in sorted(out)]


def paused(c: Client) -> list[dict[str, Any]]:
    """The paused devices, as the aliases describe them."""
    return items_of(aliases(c))


def lan_interfaces(st: nets.State) -> list[str]:
    """Interfaces with a private network of the firewall's own: not WANs."""
    out = []
    for a in st.assigned:
        if not a.enabled or not a.gateway or a.device in st.wan:
            continue
        with contextlib.suppress(ValueError):
            if ipaddress.ip_interface(a.gateway).ip.is_private:
                out.append(a.ifname)
    return out


def local_networks(lan_ipv6: list[str]) -> list[str]:
    """The private IPv4 ranges, the local IPv6 ranges and the LAN-side IPv6
    networks (e.g. the ISP's prefix on the LAN: the router and the neighbours)."""
    out = [*PRIVATE_RANGES.split("\n"), *LOCAL_IPV6]
    for addr in lan_ipv6:
        with contextlib.suppress(ValueError):
            net = ipaddress.ip_interface(addr).network
            if net.version == 6 and not net.is_link_local and str(net) not in out:
                out.append(str(net))
    return out


def pause_rules(st: nets.State, alias_name: str = PAUSED_ALIAS) -> list[dict[str, Any]]:
    return [r for r in st.rules if text(r.get("source_net")) == alias_name]


def good(r: dict[str, Any]) -> bool:
    """A pause rule as this version writes it: both families, to the local alias."""
    return (
        text(r.get("ipprotocol")) == "inet46"
        and text(r.get("destination_net")) == LOCAL_ALIAS
        and text(r.get("destination_not")) == "1"
        and text(r.get("enabled")) not in ("0", "false")
    )


def blocked(st: nets.State) -> set[str]:
    """Interfaces that have the pause rule."""
    return {i for r in pause_rules(st) if good(r) for i in text(r.get("interface")).split(",") if i}


def rule(ifname: str, sequence: int) -> dict[str, Any]:
    return {
        "enabled": "1",
        "action": "block",
        "quick": "1",
        "interface": ifname,
        "direction": "in",
        "ipprotocol": "inet46",
        "protocol": "any",
        "source_net": PAUSED_ALIAS,
        "destination_net": LOCAL_ALIAS,
        "destination_not": "1",
        "sequence": str(sequence),
        "description": RULE_DESCRIPTION,
    }


def first_sequence(st: nets.State, ifname: str) -> int:
    """A place before the interface's other rules."""
    seqs = [
        int(text(r.get("sequence")))
        for r in nets.rules_on(st, ifname)
        if text(r.get("sequence")).isdigit()
    ]
    return max(1, min(seqs, default=2) - 1)


def put_alias(c: Client, current: dict[str, Any] | None, alias: dict[str, Any]) -> bool:
    """Adds or changes an alias; whether it changed."""
    if current is not None and (
        entries(current.get("content")) == entries(alias["content"])
        and text(current.get("description")) == alias["description"]
    ):
        return False
    body = {"alias": {"enabled": "1", **alias}}
    if current is None:
        c.post(f"{ALIASES}/add_item", body)
    else:
        c.post(f"{ALIASES}/set_item/{current['uuid']}", body)
    return True


def kill_states(c: Client, ips: list[str]) -> None:
    """Cuts the open connections of these addresses; best effort (IPv4: the
    device's IPv6 addresses are not known to Omini)."""
    for ip in ips:
        with contextlib.suppress(PluginError, Forbidden, NotFound):
            c.post("/api/diagnostics/firewall/kill_states", {"filter": ip})


def sync(c: Client, st: nets.State, items: list[dict[str, Any]], lan_ipv6: list[str]) -> None:
    """Makes the aliases and rules hold exactly these paused devices; with
    none, removes everything the pause added (and what an older version did)."""
    found = aliases(c)
    old_rules = pause_rules(st, LEGACY_PAUSED_ALIAS)
    if not items:
        for r in pause_rules(st) + old_rules:
            c.post(f"{RULES}/del_rule/{r['uuid']}")
        c.post(f"{RULES}/apply")
        for name in (*PAUSED_ALIASES, LOCAL_ALIAS):
            if name in found:
                c.post(f"{ALIASES}/del_item/{found[name]['uuid']}")
        c.post(f"{ALIASES}/reconfigure")
        return
    interfaces = lan_interfaces(st)
    if not interfaces:
        raise PluginError("the firewall has no LAN-side network to pause a device on")
    changed = put_alias(
        c,
        found.get(LOCAL_ALIAS),
        {
            "name": LOCAL_ALIAS,
            "type": "network",
            "content": "\n".join(local_networks(lan_ipv6)),
            "description": "Local networks, IPv4 and IPv6 (Omini)",
        },
    )
    changed |= put_alias(
        c,
        found.get(PAUSED_ALIAS),
        {
            "name": PAUSED_ALIAS,
            "type": "mac",
            "content": "\n".join(p["mac"] for p in items),
            "description": describe(items),
        },
    )
    if changed:
        c.post(f"{ALIASES}/reconfigure")
    # Rules of an older shape (IPv4 only) go; one current rule per interface.
    have = blocked(st)
    for r in old_rules + [r for r in pause_rules(st) if not good(r)]:
        c.post(f"{RULES}/del_rule/{r['uuid']}")
    for ifname in interfaces:
        if ifname not in have:
            c.post(f"{RULES}/add_rule", {"rule": rule(ifname, first_sequence(st, ifname))})
    c.post(f"{RULES}/apply")
    if LEGACY_PAUSED_ALIAS in found:  # unused now that its rules are gone
        c.post(f"{ALIASES}/del_item/{found[LEGACY_PAUSED_ALIAS]['uuid']}")
        c.post(f"{ALIASES}/reconfigure")


def set_pause(
    c: Client,
    st: nets.State,
    want: dict[str, Any],
    lan_ipv6: list[str] | None = None,
    own_macs: set[str] | None = None,
) -> list[str]:
    """Adds the device (or replaces its addresses); the IPv4 addresses it had.
    lan_ipv6: the LAN-side interfaces' IPv6 addresses, with their prefix.
    own_macs: the firewall's own MACs, which are never paused."""
    mac = nets.norm_mac(want.get("mac"))
    if not mac:
        raise PluginError("a MAC address is needed to pause a device")
    if mac in (own_macs or set()):
        raise PluginError("the firewall itself cannot be paused")
    ips = []
    for ip in want.get("ips") or []:
        try:
            ips.append(str(ipaddress.IPv4Address(str(ip).strip())))
        except ValueError:
            continue  # IPv6: the MAC alias finds the device's addresses itself
    if not ips:
        raise PluginError("the device has no IPv4 address to pause")
    items = [p for p in paused(c) if p["mac"] != mac]
    items.append({"mac": mac, "ips": ips, "name": clean_name(want.get("name")) or None})
    sync(c, st, sorted(items, key=lambda p: p["mac"]), lan_ipv6 or [])
    kill_states(c, ips)
    return ips


def delete_pause(
    c: Client, st: nets.State, mac_value: Any, lan_ipv6: list[str] | None = None
) -> None:
    """Removes the device; the rules and the aliases go with the last one. An
    older (IPv4-only) pause is moved to the current shape on the way."""
    mac = nets.norm_mac(mac_value)
    found = aliases(c)
    items = items_of(found)
    left = [p for p in items if p["mac"] != mac]
    unchanged = len(left) == len(items) and LEGACY_PAUSED_ALIAS not in found
    if unchanged and (left or not (found or pause_rules(st))):
        return  # not paused: nothing to change
    sync(c, st, left, lan_ipv6 or [])


def is_paused(c: Client, st: nets.State, mac: str, ips: list[str]) -> bool:
    """Verification: the MAC alias holds the device, the local alias exists
    and every LAN-side network blocks them."""
    found = aliases(c)
    a = found.get(PAUSED_ALIAS)
    if a is None or LOCAL_ALIAS not in found or LEGACY_PAUSED_ALIAS in found:
        return False
    entry = next((p for p in parse(text(a.get("description"))) if p["mac"] == mac), None)
    return (
        entry is not None
        and sorted(entry["ips"]) == sorted(ips)
        and mac in entries(a.get("content"))
        and set(lan_interfaces(st)) <= blocked(st)
    )
