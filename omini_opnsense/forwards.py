"""Port forwards (Firewall → NAT → Destination NAT): the ports the firewall
sends from the internet to a device of the network. Read-only: Omini never
changes them. The MVC Destination NAT and its API (/api/firewall/d_nat) came
with OPNsense 25.7; an older firewall keeps its port forwards in the legacy
configuration, which has no API, and reports none."""

from __future__ import annotations

import ipaddress
from typing import Any

from omini_opnsense.client import Client
from omini_opnsense.networks import rows, text

SEARCH = "/api/firewall/d_nat/search_rule"

PROTOCOLS = {"tcp": "tcp", "udp": "udp", "tcp/udp": "tcp/udp"}

# Well-known names OPNsense accepts in a port field (its own list is longer;
# a name not here leaves the forward out rather than guessing its port).
WELL_KNOWN = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "http": 80,
    "pop3": 110,
    "ntp": 123,
    "imap": 143,
    "snmp": 161,
    "ldap": 389,
    "https": 443,
    "smtps": 465,
    "submission": 587,
    "imaps": 993,
    "pop3s": 995,
    "openvpn": 1194,
    "ms-wbt-server": 3389,
    "rdp": 3389,
}


def port(value: str) -> int | None:
    v = value.strip().lower()
    n = WELL_KNOWN.get(v) if not v.isdigit() else int(v)
    return n if n and 1 <= n <= 65535 else None


def port_range(value: Any) -> tuple[int, int | None] | None:
    """'443', 'https', '8000-8010' or '8000:8010' → (first, last or None);
    None for an alias or an empty field."""
    v = text(value)
    for sep in ("-", ":"):
        if sep in v:
            a, _, b = v.partition(sep)
            first, last = port(a), port(b)
            if first is None or last is None or last < first:
                return None
            return first, (last if last != first else None)
    first = port(v) if v else None
    return (first, None) if first else None


def address(value: Any) -> str | None:
    """An IP address or network; None for "any", an alias or an interface's net."""
    v = text(value)
    if not v or v.lower() == "any":
        return None
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        return None
    return v


def disabled(r: dict[str, Any]) -> bool:
    if "disabled" in r:
        return text(r.get("disabled")) in ("1", "true", "True")
    return text(r.get("enabled")) in ("0", "false")


def forwards(c: Client, logical: dict[str, str]) -> list[dict[str, Any]]:
    """Each port forward as a PortForward's fields. logical: lan → igb1."""
    out = []
    for r in rows(c, SEARCH):
        if text(r.get("nordr")) in ("1", "true"):
            continue  # "no redirect": an exception, not a forward
        proto = PROTOCOLS.get(text(r.get("protocol")).lower())
        ext = port_range(r.get("destination.port"))
        if not proto or not ext:
            continue
        local = port_range(r.get("local-port"))
        ifname = text(r.get("interface")).split(",")[0]
        target = text(r.get("target"))
        source = address(r.get("source.network"))
        if text(r.get("source.not")) in ("1", "true"):
            source = None  # "anyone but…" is reported as anyone
        out.append(
            {
                "protocol": proto,
                "external_port": ext[0],
                "external_port_end": ext[1],
                "internal_ip": target if address(target) and "/" not in target else None,
                "internal_port": local[0] if local else None,
                "source": source,
                "interface": logical.get(ifname, ifname) or None,
                "description": text(r.get("descr")) or None,
                "enabled": not disabled(r),
                "upnp": False,
            }
        )
    return out
