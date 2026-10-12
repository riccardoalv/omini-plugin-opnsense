"""Pausing a device's internet: the host alias omini_paused holds the paused
addresses (its description keeps which MAC each one belongs to) and one block
rule per LAN-side interface stops them from reaching anything that is not a
private network. pause.set and pause.delete change them; collect reports
Device.paused."""

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
    PAUSED_ALIAS,
    PRIVATE_ALIAS,
    RULE_PREFIX,
    RULES,
    rows,
    text,
)

DESCRIPTION = "Omini paused:"
RULE_DESCRIPTION = f"{RULE_PREFIX}paused devices (no internet)"
ENTRY = re.compile(r"^([0-9a-f]{2}(?::[0-9a-f]{2}){5})((?: [0-9.]+)*)(?: \((.*)\))?$")


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


def alias(c: Client) -> dict[str, Any] | None:
    return next(
        (a for a in rows(c, f"{ALIASES}/search_item") if text(a.get("name")) == PAUSED_ALIAS),
        None,
    )


def paused(c: Client) -> list[dict[str, Any]]:
    """The paused devices, as the alias describes them."""
    a = alias(c)
    return parse(text(a.get("description"))) if a else []


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


def pause_rules(st: nets.State) -> list[dict[str, Any]]:
    return [r for r in st.rules if text(r.get("source_net")) == PAUSED_ALIAS]


def blocked(st: nets.State) -> set[str]:
    """Interfaces that have the pause rule."""
    return {i for r in pause_rules(st) for i in text(r.get("interface")).split(",") if i}


def rule(ifname: str, sequence: int) -> dict[str, Any]:
    return {
        "enabled": "1",
        "action": "block",
        "quick": "1",
        "interface": ifname,
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "any",
        "source_net": PAUSED_ALIAS,
        "destination_net": PRIVATE_ALIAS,
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


def write_alias(c: Client, current: dict[str, Any] | None, items: list[dict[str, Any]]) -> None:
    ips = sorted({ip for p in items for ip in p["ips"]}, key=ipaddress.IPv4Address)
    body = {
        "alias": {
            "enabled": "1",
            "name": PAUSED_ALIAS,
            "type": "host",
            "content": "\n".join(ips),
            "description": describe(items),
        }
    }
    if current is None:
        c.post(f"{ALIASES}/add_item", body)
    else:
        c.post(f"{ALIASES}/set_item/{current['uuid']}", body)
    c.post(f"{ALIASES}/reconfigure")


def kill_states(c: Client, ips: list[str]) -> None:
    """Cuts the open connections of these addresses; best effort."""
    for ip in ips:
        with contextlib.suppress(PluginError, Forbidden, NotFound):
            c.post("/api/diagnostics/firewall/kill_states", {"filter": ip})


def set_pause(c: Client, st: nets.State, want: dict[str, Any]) -> list[str]:
    """Adds the device (or replaces its addresses); the addresses blocked."""
    mac = nets.norm_mac(want.get("mac"))
    if not mac:
        raise PluginError("a MAC address is needed to pause a device")
    ips = []
    for ip in want.get("ips") or []:
        try:
            ips.append(str(ipaddress.IPv4Address(str(ip).strip())))
        except ValueError:
            continue  # IPv6: the rule is IPv4 only
    if not ips:
        raise PluginError("the device has no IPv4 address to pause")
    interfaces = lan_interfaces(st)
    if not interfaces:
        raise PluginError("the firewall has no LAN-side network to pause a device on")
    nets.ensure_private_alias(c)
    current = alias(c)
    items = [
        p for p in (parse(text(current.get("description"))) if current else []) if p["mac"] != mac
    ]
    items.append({"mac": mac, "ips": ips, "name": clean_name(want.get("name")) or None})
    write_alias(c, current, items)
    missing = [i for i in interfaces if i not in blocked(st)]
    for ifname in missing:
        c.post(f"{RULES}/add_rule", {"rule": rule(ifname, first_sequence(st, ifname))})
    c.post(f"{RULES}/apply")
    kill_states(c, ips)
    return ips


def delete_pause(c: Client, st: nets.State, mac_value: Any) -> None:
    """Removes the device's addresses; the rules and the alias go with the last one."""
    mac = nets.norm_mac(mac_value)
    current = alias(c)
    if current is None:
        return
    items = parse(text(current.get("description")))
    left = [p for p in items if p["mac"] != mac]
    if left:
        if len(left) != len(items):
            write_alias(c, current, left)
        return
    for r in pause_rules(st):
        c.post(f"{RULES}/del_rule/{r['uuid']}")
    c.post(f"{RULES}/apply")
    c.post(f"{ALIASES}/del_item/{current['uuid']}")
    c.post(f"{ALIASES}/reconfigure")


def is_paused(c: Client, st: nets.State, mac: str, ips: list[str]) -> bool:
    """Verification: the alias holds the addresses and every LAN-side network blocks them."""
    a = alias(c)
    if a is None:
        return False
    content = set(re.split(r"[\s,]+", text(a.get("content"))))
    entry = next((p for p in parse(text(a.get("description"))) if p["mac"] == mac), None)
    return (
        entry is not None
        and sorted(entry["ips"]) == sorted(ips)
        and set(ips) <= content
        and set(lan_interfaces(st)) <= blocked(st)
    )
