"""Local DNS names on OPNsense: Unbound host overrides when Unbound is the
DNS server, else dnsmasq hosts. Read every round (Device.dns_records) and
changed by dns.set and dns.delete."""

from __future__ import annotations

import contextlib
from typing import Any

from omini_sdk import PluginError

from omini_opnsense.client import Client, Forbidden, NotFound
from omini_opnsense.networks import rows, text

UNBOUND = "/api/unbound/settings"
DNSMASQ = "/api/dnsmasq/settings"
MARK = "Omini"


def server(c: Client) -> str | None:
    """Which DNS server answers: "unbound", "dnsmasq" or None."""
    with contextlib.suppress(NotFound):
        general = (c.get(f"{UNBOUND}/get").get("unbound") or {}).get("general") or {}
        if text(general.get("enabled")) == "1":
            return "unbound"
    with contextlib.suppress(NotFound):
        d = c.get(f"{DNSMASQ}/get").get("dnsmasq") or {}
        # dnsmasq serving only DHCP has its DNS port at 0.
        if text(d.get("enable")) == "1" and text(d.get("port")) != "0":
            return "dnsmasq"
    return None


def dhcp_domain(c: Client) -> str:
    """The domain dnsmasq hands out, when it has one."""
    with contextlib.suppress(NotFound, Forbidden):
        d = c.get(f"{DNSMASQ}/get").get("dnsmasq") or {}
        return text(d.get("domain") or (d.get("dhcp") or {}).get("domain")).lower()
    return ""


def domain_of(system_name: str, c: Client | None = None) -> str | None:
    """The system's domain (fw.example.lan → example.lan), else the DHCP one."""
    _, _, dom = system_name.strip().lower().partition(".")
    if not dom and c is not None:
        dom = dhcp_domain(c)
    return dom or None


def is_a(rr: Any) -> bool:
    """'A', or 'A (IPv4 address)' as the search grid shows it; never AAAA or MX."""
    v = text(rr).split(" ")[0].upper()
    return v in ("A", "")


def entries(c: Client, kind: str, domain: str | None) -> list[dict[str, Any]]:
    """Each local name: {uuid, name (fully qualified), ip, hwaddr}."""
    out = []
    if kind == "unbound":
        for r in rows(c, f"{UNBOUND}/search_host_override"):
            host, dom, ip = text(r.get("hostname")), text(r.get("domain")), text(r.get("server"))
            if text(r.get("enabled")) in ("0", "false") or not is_a(r.get("rr")) or "." not in ip:
                continue
            if not host or host == "*":
                continue
            out.append({"uuid": r.get("uuid"), "name": f"{host}.{dom}".lower(), "ip": ip})
    elif kind == "dnsmasq":
        for r in rows(c, f"{DNSMASQ}/search_host"):
            host, ip = text(r.get("host")), text(r.get("ip")).split(",")[0]
            if not host or "." not in ip:
                continue
            dom = text(r.get("domain")) or domain or ""
            name = f"{host}.{dom}" if dom else host
            out.append(
                {
                    "uuid": r.get("uuid"),
                    "name": name.lower(),
                    "ip": ip,
                    "hwaddr": text(r.get("hwaddr")),
                }
            )
    return out


def records(c: Client, domain: str | None) -> list[dict[str, str]]:
    kind = server(c)
    if kind is None:
        return []
    found = {(e["name"], e["ip"]) for e in entries(c, kind, domain)}
    return [{"name": n, "ip": ip} for n, ip in sorted(found)]


def split(name: str, domain: str | None) -> tuple[str, str]:
    name = name.strip().rstrip(".").lower()
    host, _, dom = name.partition(".")
    dom = dom or domain or ""
    if not host:
        raise PluginError("a DNS name is needed")
    if not dom:
        raise PluginError(f"{name} has no domain and the firewall has none")
    return host, dom


def set_name(c: Client, want: dict[str, Any], domain: str | None) -> str:
    """Creates the name or changes its address; the fully qualified name."""
    kind = server(c)
    if kind is None:
        raise PluginError("neither Unbound nor dnsmasq answers DNS on this firewall")
    host, dom = split(str(want.get("name") or ""), domain)
    ip = str(want.get("ip") or "")
    if "." not in ip:
        raise PluginError("an IPv4 address is needed for the name")
    fqdn = f"{host}.{dom}"
    current = next((e for e in entries(c, kind, domain) if e["name"] == fqdn), None)
    if kind == "unbound":
        body = {
            "host": {
                "enabled": "1",
                "hostname": host,
                "domain": dom,
                "rr": "A",
                "server": ip,
                "description": MARK,
            }
        }
        if current is None:
            c.post(f"{UNBOUND}/add_host_override", body)
        elif current["ip"] != ip:
            c.post(f"{UNBOUND}/set_host_override/{current['uuid']}", body)
        else:
            return fqdn
        c.post("/api/unbound/service/reconfigure")
        return fqdn
    body = {"host": {"host": host, "domain": dom, "ip": ip, "descr": MARK}}
    if current is None:
        c.post(f"{DNSMASQ}/add_host", body)
    elif current["ip"] != ip:
        if current.get("hwaddr"):
            # The entry is also a fixed address: keep its MAC and name.
            body["host"].pop("descr")
        c.post(f"{DNSMASQ}/set_host/{current['uuid']}", body)
    else:
        return fqdn
    c.post("/api/dnsmasq/service/reconfigure")
    return fqdn


def delete_name(c: Client, name: str, domain: str | None) -> str:
    """Removes the name; one that is not there is already removed."""
    kind = server(c)
    if kind is None:
        raise PluginError("neither Unbound nor dnsmasq answers DNS on this firewall")
    host, dom = split(name, domain)
    fqdn = f"{host}.{dom}"
    found = [e for e in entries(c, kind, domain) if e["name"] == fqdn]
    if not found:
        return fqdn
    for e in found:
        if kind == "unbound":
            c.post(f"{UNBOUND}/del_host_override/{e['uuid']}")
        elif e.get("hwaddr"):
            raise PluginError(
                f"{fqdn} is the name of the fixed address of {e['hwaddr']}: "
                "free the address to remove it"
            )
        else:
            c.post(f"{DNSMASQ}/del_host/{e['uuid']}")
    c.post(f"/api/{kind}/service/reconfigure")
    return fqdn
