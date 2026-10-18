"""A VLAN's network on OPNsense: its interface, gateway, DHCP (Kea or dnsmasq)
and access rules. Read for every round, and changed by network.set and
network.delete through the API of OPNsense 26.7 or later (interface
assignments came to the API in 26.7)."""

from __future__ import annotations

import contextlib
import ipaddress
import re
import time
from dataclasses import dataclass, field
from typing import Any

from omini_sdk import PluginError

from omini_opnsense.client import Client, Forbidden, NotFound

ASSIGNMENTS = "/api/interfaces/assignment"
VLANS = "/api/interfaces/vlan_settings"
KEA = "/api/kea/dhcpv4"
DNSMASQ = "/api/dnsmasq/settings"
RULES = "/api/firewall/filter"
ALIASES = "/api/firewall/alias"
MDNS = "/api/mdnsrepeater"  # the os-mdns-repeater plugin

# The private ranges, an alias the "Internet only" rules block.
PRIVATE_ALIAS = "omini_private"
PRIVATE_RANGES = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16"
# The paused devices' MACs (see pause.py); its rules are no network's access.
PAUSED_ALIAS = "omini_paused_mac"
# Before 0.5.1: the paused devices' IPv4 addresses (migrated by the next pause or resume).
LEGACY_PAUSED_ALIAS = "omini_paused"
PAUSED_ALIASES = (PAUSED_ALIAS, LEGACY_PAUSED_ALIAS)
# Rules Omini writes start with this, so a person reading them knows.
RULE_PREFIX = "Omini: "


def rows(c: Client, path: str, **params: Any) -> list[dict[str, Any]]:
    data = c.get(path, params={"rowCount": -1, **params})
    return list(data.get("rows") or []) if isinstance(data, dict) else []


def text(value: Any) -> str:
    """A field as OPNsense answers it: a plain string, or a select
    ({"value": {"selected": 1}}) whose selected keys are the value."""
    if isinstance(value, dict):
        return ",".join(k for k, v in value.items() if isinstance(v, dict) and v.get("selected"))
    return "" if value is None else str(value).strip()


@dataclass
class Assigned:
    """An interface assignment: lan, opt3..."""

    ifname: str
    device: str
    descr: str
    gateway: str  # "192.168.30.1/24", "" when not static
    enabled: bool


@dataclass
class State:
    """What the router has, read once per change or round."""

    assigned: list[Assigned] = field(default_factory=list)
    vlans: dict[str, dict[str, Any]] = field(default_factory=dict)  # device → {uuid, tag, parent}
    wan: set[str] = field(default_factory=set)  # devices that are WANs or carry one
    kea: bool = False
    kea_interfaces: list[str] = field(default_factory=list)
    subnets: list[dict[str, Any]] = field(default_factory=list)
    ranges: list[dict[str, Any]] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)
    mdns: list[str] | None = None  # the repeater's interfaces; None: the plugin is not installed
    mdns_on: bool = False  # the repeater runs (two or more interfaces)


def read_state(c: Client, wan_devices: set[str]) -> State | None:
    """The router's networks as the API shows them; None before 26.7 (no
    assignments API) or without the privilege."""
    try:
        assigned_rows = rows(c, f"{ASSIGNMENTS}/search_item")
    except (NotFound, Forbidden):
        return None
    st = State(wan=set(wan_devices))
    for r in assigned_rows:
        ifname = text(r.get("identifier") or r.get("ifname") or r.get("uuid"))
        device = text(r.get("if") or r.get("device"))
        if not ifname or not device:
            continue
        gw = text(r.get("ipaddr")) if text(r.get("type4")) == "staticv4" else ""
        if gw and "/" not in gw and text(r.get("subnet")):
            gw = f"{gw}/{text(r.get('subnet'))}"
        st.assigned.append(
            Assigned(
                ifname=ifname,
                device=device,
                descr=text(r.get("descr") or r.get("description")),
                gateway=gw,
                enabled=text(r.get("enable")) in ("1", "true", "True"),
            )
        )
    for r in rows(c, f"{VLANS}/search_item"):
        device = text(r.get("vlanif")).split(" ")[0]
        if device:
            st.vlans[device] = {
                "uuid": r.get("uuid"),
                "tag": int(text(r.get("tag")) or 0),
                "parent": text(r.get("if")).split(" ")[0],
            }
    try:
        general = (c.get(f"{KEA}/get").get("dhcpv4") or {}).get("general") or {}
        st.kea = text(general.get("enabled")) == "1"
        st.kea_interfaces = [i for i in text(general.get("interfaces")).split(",") if i]
        st.subnets = rows(c, f"{KEA}/search_subnet")
    except (NotFound, Forbidden):
        pass
    if not st.kea:
        with contextlib.suppress(NotFound, Forbidden):
            st.ranges = rows(c, f"{DNSMASQ}/search_range")
    with contextlib.suppress(NotFound, Forbidden):
        st.rules = rows(c, f"{RULES}/search_rule")
    with contextlib.suppress(NotFound, Forbidden):
        repeater = c.get(f"{MDNS}/settings/get").get("mdnsrepeater") or {}
        st.mdns_on = text(repeater.get("enabled")) == "1"
        st.mdns = [i for i in text(repeater.get("interfaces")).split(",") if i]
    return st


def vlan_of(st: State, a: Assigned) -> int | None:
    """The VLAN an interface serves: its VLAN device's tag; the LAN is VLAN 1."""
    if a.device in st.vlans:
        return st.vlans[a.device]["tag"] or None
    return 1 if a.ifname == "lan" else None


def dhcp_of(st: State, a: Assigned) -> dict[str, Any] | None:
    if not a.gateway:
        return None
    net = ipaddress.ip_interface(a.gateway).network
    if st.kea:
        if a.ifname not in st.kea_interfaces:
            return {"enabled": False}
        for s in st.subnets:
            if text(s.get("subnet")) == str(net):
                first = text(s.get("pools")).replace("\n", ",").split(",")[0]
                if "-" in first:
                    lo, hi = (p.strip() for p in first.split("-", 1))
                    return {"enabled": True, "from": lo, "to": hi}
        return {"enabled": False}
    for r in st.ranges:
        if text(r.get("interface")) == a.ifname and r.get("start_addr") and r.get("end_addr"):
            return {"enabled": True, "from": text(r["start_addr"]), "to": text(r["end_addr"])}
    return {"enabled": False}


def rules_on(st: State, ifname: str) -> list[dict[str, Any]]:
    """The interface's rules, but the pause rule (it belongs to no network's access)."""
    return [
        r
        for r in st.rules
        if ifname in text(r.get("interface")).lower().split(",")
        and text(r.get("enabled")) not in ("0", "false")
        and text(r.get("source_net")) not in PAUSED_ALIASES
    ]


def own_rules(st: State, ifname: str) -> list[dict[str, Any]]:
    """The interface's rules that are its alone: a floating rule (several
    interfaces, or all but some) serves others too, so it is no network's
    access and Omini never deletes it."""
    return [
        r
        for r in rules_on(st, ifname)
        if text(r.get("interface")).lower().split(",") == [ifname]
        and text(r.get("interfacenot")) != "1"
        and text(r.get("floating")) != "1"
    ]


def rule_shape(r: dict[str, Any], ifname: str) -> str:
    """A rule as one of the presets' pieces: dns, block_private, pass_any or other."""
    action = text(r.get("action")).lower()
    src = text(r.get("source_net")).lower()
    dst = text(r.get("destination_net")).lower()
    port = text(r.get("destination_port")).lower()
    if src not in (ifname, f"{ifname}net", "") or text(r.get("source_not")) == "1":
        return "other"
    if action == "pass" and dst in ("any", "") and text(r.get("destination_not")) != "1":
        return "pass_any"
    if action in ("block", "reject") and dst == PRIVATE_ALIAS:
        return "block_private"
    if action == "pass" and dst in (f"{ifname}ip", "(self)") and port in ("53", "domain", "dns"):
        return "dns"
    return "other"


def access_of(st: State, ifname: str) -> str:
    """Which of the three choices the interface's rules are, else custom."""
    shapes = [rule_shape(r, ifname) for r in own_rules(st, ifname)]
    if not shapes or "other" in shapes:
        return "custom"
    core = [s for s in shapes if s != "dns"]
    if core == ["pass_any"]:
        return "all"
    if core == ["block_private", "pass_any"]:
        return "internet"
    if not core:
        return "local"
    return "custom"


def networks(st: State) -> list[dict[str, Any]]:
    """Each VLAN's network: the statically addressed interfaces, but WANs."""
    out = []
    for a in st.assigned:
        vid = vlan_of(st, a)
        if not vid or not a.gateway or a.device in st.wan:
            continue
        try:
            if not ipaddress.ip_interface(a.gateway).ip.is_private:
                continue
        except ValueError:
            continue
        out.append(
            {
                "vlan": vid,
                "name": a.descr or None,
                "interface": a.ifname,
                "device": a.device,
                "parent": (st.vlans.get(a.device) or {}).get("parent") or None,
                "gateway": a.gateway,
                "dhcp": dhcp_of(st, a),
                "access": access_of(st, a.ifname),
                "mdns": (st.mdns_on and a.ifname in st.mdns) if st.mdns is not None else None,
            }
        )
    return sorted(out, key=lambda n: n["vlan"])


# --- changes ------------------------------------------------------------------


def physical_parent(_c: Client, parent: str, bridges: dict[str, list[str]]) -> str:
    """A VLAN rides on a port, not on a bridge: a bridge's first physical member."""
    members = bridges.get(parent)
    if not members:
        return parent
    physical = [m for m in members if not m.startswith(("vtnet", "tap", "vlan", "gif", "gre"))]
    return (physical or members)[0]


def ensure_vlan(c: Client, st: State, vid: int, parent: str, name: str) -> str:
    """The VLAN device on parent (vlan0.30), created when missing."""
    for device, v in st.vlans.items():
        if v["tag"] == vid and (not parent or v["parent"] == parent):
            return device
    if not parent:
        raise PluginError(
            f"no port to put VLAN {vid} on: name the router's port toward the switches"
        )
    c.post(
        f"{VLANS}/add_item",
        {"vlan": {"if": parent, "tag": str(vid), "pcp": "0", "proto": "", "descr": name}},
    )
    c.post(f"{VLANS}/reconfigure")
    for r in rows(c, f"{VLANS}/search_item"):
        if int(text(r.get("tag")) or 0) == vid and text(r.get("if")).split(" ")[0] == parent:
            device = text(r.get("vlanif")).split(" ")[0]
            st.vlans[device] = {"uuid": r.get("uuid"), "tag": vid, "parent": parent}
            return device
    raise PluginError(f"OPNsense did not create VLAN {vid} on {parent}")


def ensure_assigned(c: Client, st: State, device: str, name: str, gateway: str) -> str:
    """The interface on the device with the gateway address; its name (opt3)."""
    body = {
        "interface": {
            "if": device,
            "descr": name,
            "enable": "1",
            "type4": "staticv4",
            "ipaddr": gateway,
        }
    }
    current = next((a for a in st.assigned if a.device == device), None)
    if current is None:
        c.post(f"{ASSIGNMENTS}/add_item", body)
    elif (current.descr, current.gateway, current.enabled) != (
        name or current.descr,
        gateway,
        True,
    ):
        if not name:
            body["interface"]["descr"] = current.descr
        c.post(f"{ASSIGNMENTS}/set_item/{current.ifname}", body)
    else:
        return current.ifname
    c.post(f"{ASSIGNMENTS}/reconfigure")
    for r in rows(c, f"{ASSIGNMENTS}/search_item"):
        if text(r.get("if") or r.get("device")) == device:
            return text(r.get("identifier") or r.get("ifname") or r.get("uuid"))
    raise PluginError(f"OPNsense did not assign {device}")


def set_dhcp(
    c: Client, st: State, ifname: str, gateway: str, dhcp: dict[str, Any] | None, name: str
) -> None:
    net = str(ipaddress.ip_interface(gateway).network)
    on = bool(dhcp and dhcp.get("enabled"))
    if st.kea:
        subnet = next((s for s in st.subnets if text(s.get("subnet")) == net), None)
        if on:
            pools = f"{dhcp['from']}-{dhcp['to']}"
            body = {
                "subnet4": {
                    "subnet": net,
                    "pools": pools,
                    "option_data_autocollect": "1",
                    "description": name,
                }
            }
            if subnet is None:
                c.post(f"{KEA}/add_subnet", body)
            elif text(subnet.get("pools")).split(",")[0].replace(" ", "") != pools:
                c.post(f"{KEA}/set_subnet/{subnet['uuid']}", body)
            if ifname not in st.kea_interfaces:
                st.kea_interfaces.append(ifname)
                c.post(
                    f"{KEA}/set",
                    {"dhcpv4": {"general": {"interfaces": ",".join(st.kea_interfaces)}}},
                )
        else:
            if subnet is not None:
                c.post(f"{KEA}/del_subnet/{subnet['uuid']}")
            if ifname in st.kea_interfaces:
                st.kea_interfaces.remove(ifname)
                c.post(
                    f"{KEA}/set",
                    {"dhcpv4": {"general": {"interfaces": ",".join(st.kea_interfaces)}}},
                )
        c.post("/api/kea/service/reconfigure")
        return
    current = next((r for r in st.ranges if text(r.get("interface")) == ifname), None)
    if on:
        body = {
            "range": {
                "interface": ifname,
                "start_addr": dhcp["from"],
                "end_addr": dhcp["to"],
                "description": name,
            }
        }
        if current is None:
            c.post(f"{DNSMASQ}/add_range", body)
        else:
            c.post(f"{DNSMASQ}/set_range/{current['uuid']}", body)
    elif current is not None:
        c.post(f"{DNSMASQ}/del_range/{current['uuid']}")
    c.post("/api/dnsmasq/service/reconfigure")


def ensure_private_alias(c: Client) -> None:
    if any(text(a.get("name")) == PRIVATE_ALIAS for a in rows(c, f"{ALIASES}/search_item")):
        return
    c.post(
        f"{ALIASES}/add_item",
        {
            "alias": {
                "enabled": "1",
                "name": PRIVATE_ALIAS,
                "type": "network",
                "content": PRIVATE_RANGES,
                "description": "Private networks (Omini)",
            }
        },
    )
    c.post(f"{ALIASES}/reconfigure")


def preset_rules(access: str, ifname: str, name: str) -> list[dict[str, Any]]:
    def rule(action: str, dst: str, what: str, **extra: str) -> dict[str, Any]:
        return {
            "enabled": "1",
            "action": action,
            "quick": "1",
            "interface": ifname,
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": ifname,
            "destination_net": dst,
            "description": f"{RULE_PREFIX}{name or ifname} {what}",
            **extra,
        }

    dns = rule("pass", f"{ifname}ip", "DNS", protocol="TCP/UDP", destination_port="53")
    if access == "all":
        return [rule("pass", "any", "to everything")]
    if access == "internet":
        return [
            dns,
            rule("block", PRIVATE_ALIAS, "not to other networks"),
            rule("pass", "any", "to the internet"),
        ]
    return [dns]  # local: its own network only


def set_access(c: Client, st: State, ifname: str, access: str | None, name: str) -> None:
    """Replaces the interface's rules with the chosen access; custom (or none)
    leaves them as they are."""
    if access not in ("internet", "all", "local") or access_of(st, ifname) == access:
        return
    if access == "internet":
        ensure_private_alias(c)
    for r in own_rules(st, ifname):
        c.post(f"{RULES}/del_rule/{r['uuid']}")
    for r in preset_rules(access, ifname, name):
        c.post(f"{RULES}/add_rule", {"rule": r})
    c.post(f"{RULES}/apply")


def drop_rules(c: Client, st: State, ifname: str) -> None:
    for r in own_rules(st, ifname):
        c.post(f"{RULES}/del_rule/{r['uuid']}")
    c.post(f"{RULES}/apply")


def apply_set(c: Client, st: State, want: dict[str, Any], bridges: dict[str, list[str]]) -> None:
    vid = int(want["vlan"])
    name = str(want.get("name") or "")
    gateway = str(want["gateway"])
    existing = next((n for n in networks(st) if n["vlan"] == vid), None)
    if existing:
        device = existing["device"]
    elif vid == 1:
        raise PluginError("the router has no LAN to change")
    else:
        parent = physical_parent(c, str(want.get("parent") or ""), bridges)
        device = ensure_vlan(c, st, vid, parent, name)
    ifname = ensure_assigned(c, st, device, name, gateway)
    set_dhcp(c, st, ifname, gateway, want.get("dhcp"), name)
    set_access(c, st, ifname, want.get("access"), name)
    if want.get("mdns") is not None:
        set_mdns(c, st, ifname, bool(want["mdns"]))


def set_mdns(c: Client, st: State, ifname: str, on: bool) -> None:
    """Discovery between networks: the interface joins or leaves the mDNS
    repeater, which runs while two or more networks are in it."""
    if st.mdns is None:
        if on:
            raise PluginError(
                "discovery between VLANs needs the os-mdns-repeater plugin: "
                "install it in System → Firmware → Plugins"
            )
        return
    if (ifname in st.mdns) == on and st.mdns_on == (len(st.mdns) >= 2):
        return
    wanted = [i for i in st.mdns if i != ifname] + ([ifname] if on else [])
    st.mdns, st.mdns_on = wanted, len(wanted) >= 2
    c.post(
        f"{MDNS}/settings/set",
        {
            "mdnsrepeater": {
                "enabled": "1" if len(wanted) >= 2 else "0",
                "interfaces": ",".join(wanted),
            }
        },
    )
    c.post(f"{MDNS}/service/reconfigure")


def apply_delete(c: Client, st: State, vid: int) -> None:
    if vid == 1:
        raise PluginError("the LAN cannot be removed from Omini")
    n = next((n for n in networks(st) if n["vlan"] == vid), None)
    if n is None:
        raise PluginError(f"the router serves no network on VLAN {vid}")
    ifname, device = n["interface"], n["device"]
    for r in st.rules:  # its pause rule, if a device is paused
        if text(r.get("source_net")) in PAUSED_ALIASES and text(r.get("interface")) == ifname:
            c.post(f"{RULES}/del_rule/{r['uuid']}")
    drop_rules(c, st, ifname)
    set_mdns(c, st, ifname, False)
    set_dhcp(c, st, ifname, n["gateway"], {"enabled": False}, "")
    c.post(f"{ASSIGNMENTS}/del_item/{ifname}")
    c.post(f"{ASSIGNMENTS}/reconfigure")
    v = st.vlans.get(device)
    if v and v.get("uuid"):
        c.post(f"{VLANS}/del_item/{v['uuid']}")
        c.post(f"{VLANS}/reconfigure")


def wait_for(check, what: str, tries: int = 10, pause: float = 1.0) -> None:
    """Interfaces come up a moment after reconfigure: reads again until check holds."""
    for i in range(tries):
        if check():
            return
        if i < tries - 1:
            time.sleep(pause)
    raise PluginError(f"OPNsense did not apply {what}")


def matches(st: State | None, want: dict[str, Any]) -> bool:
    """Whether the router serves want as asked."""
    if st is None:
        return False
    have = next((n for n in networks(st) if n["vlan"] == int(want["vlan"])), None)
    if have is None or have["gateway"] != want.get("gateway"):
        return False
    d, h = want.get("dhcp") or {"enabled": False}, have.get("dhcp") or {"enabled": False}
    if bool(d.get("enabled")) != bool(h.get("enabled")):
        return False
    if d.get("enabled") and (d.get("from"), d.get("to")) != (h.get("from"), h.get("to")):
        return False
    access = want.get("access")
    if access in ("internet", "all", "local") and have["access"] != access:
        return False
    mdns = want.get("mdns")
    if mdns is None or have.get("mdns") is None or bool(have["mdns"]) == bool(mdns):
        return True
    # Asked on, but the only network in the repeater: it starts with a second one.
    return bool(mdns) and st.mdns == [have["interface"]]


# --- reservations (a fixed address for a MAC) -----------------------------------


def norm_mac(value: Any) -> str:
    raw = re.sub(r"[^0-9a-f]", "", text(value).lower())
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2)) if len(raw) == 12 else ""


def hostname(name: str) -> str:
    """A name DHCP can hand out: letters, digits and dashes."""
    out = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return out[:63] or "device"


def reservations(c: Client, st: State) -> list[dict[str, Any]]:
    """The fixed addresses of Kea (when it is on) or dnsmasq."""
    out = []
    try:
        if st.kea:
            for r in rows(c, f"{KEA}/search_reservation"):
                mac = norm_mac(r.get("hw_address"))
                if mac and r.get("ip_address"):
                    out.append(
                        {
                            "mac": mac,
                            "ip": text(r["ip_address"]),
                            "name": text(r.get("hostname")) or None,
                        }
                    )
        else:
            for r in rows(c, f"{DNSMASQ}/search_host"):
                mac = norm_mac(r.get("hwaddr"))
                if mac and r.get("ip"):
                    out.append(
                        {"mac": mac, "ip": text(r["ip"]), "name": text(r.get("host")) or None}
                    )
    except (NotFound, Forbidden):
        return []
    return out


def reserve(c: Client, st: State, want: dict[str, Any]) -> None:
    mac, ip = norm_mac(want.get("mac")), str(want.get("ip") or "")
    name = hostname(str(want.get("name") or ""))
    addr = ipaddress.IPv4Address(ip)
    if st.kea:
        subnet = next(
            (
                s
                for s in st.subnets
                if addr in ipaddress.ip_network(text(s.get("subnet")), strict=False)
            ),
            None,
        )
        if subnet is None:
            raise PluginError(f"Kea has no subnet for {ip}: turn DHCP on in that network first")
        body = {
            "reservation": {
                "subnet": subnet["uuid"],
                "ip_address": ip,
                "hw_address": mac,
                "hostname": name,
                "description": "Omini",
            }
        }
        current = next(
            (
                r
                for r in rows(c, f"{KEA}/search_reservation")
                if norm_mac(r.get("hw_address")) == mac
            ),
            None,
        )
        if current is None:
            c.post(f"{KEA}/add_reservation", body)
        else:
            c.post(f"{KEA}/set_reservation/{current['uuid']}", body)
        c.post("/api/kea/service/reconfigure")
        return
    body = {"host": {"host": name, "ip": ip, "hwaddr": mac, "descr": "Omini"}}
    current = next(
        (r for r in rows(c, f"{DNSMASQ}/search_host") if norm_mac(r.get("hwaddr")) == mac), None
    )
    if current is None:
        c.post(f"{DNSMASQ}/add_host", body)
    else:
        c.post(f"{DNSMASQ}/set_host/{current['uuid']}", body)
    c.post("/api/dnsmasq/service/reconfigure")


def unreserve(c: Client, st: State, mac_value: Any) -> None:
    mac = norm_mac(mac_value)
    if st.kea:
        for r in rows(c, f"{KEA}/search_reservation"):
            if norm_mac(r.get("hw_address")) == mac:
                c.post(f"{KEA}/del_reservation/{r['uuid']}")
        c.post("/api/kea/service/reconfigure")
        return
    for r in rows(c, f"{DNSMASQ}/search_host"):
        if norm_mac(r.get("hwaddr")) == mac:
            c.post(f"{DNSMASQ}/del_host/{r['uuid']}")
    c.post("/api/dnsmasq/service/reconfigure")
