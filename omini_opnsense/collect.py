"""Turns OPNsense API answers into Omini devices."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any, TypeVar
from urllib.parse import urlparse

from omini_sdk import (
    ArpEntry,
    Config,
    Device,
    DhcpLease,
    Gateway,
    Interface,
    PluginError,
    log,
)

from omini_opnsense.client import Client, Forbidden, NotFound

T = TypeVar("T")

# Pseudo interfaces that are not ports.
SKIP = re.compile(r"^(lo|enc|pflog|pfsync|ipfw)\d*$")

MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

# Privilege (as named in System → Access → Users) per piece of data.
PRIVILEGES = {
    "interfaces": "Status: Interfaces",
    "traffic": "Reporting: Traffic",
    "arp": "Diagnostics: ARP Table",
    "dhcp": "Status: DHCP leases (ISC), Services: DHCP: Kea(v4) or Services: Dnsmasq DNS/DHCP",
    "system": "Lobby: Dashboard",
    "gateways": "System: Gateways",
}


def client_from(cfg: Config) -> Client:
    url, key, secret = cfg.str("url"), cfg.str("api_key"), cfg.str("api_secret")
    if not url or not key or not secret:
        raise PluginError("the address, API key and API secret are required")
    return Client(url, key, secret, verify_tls=cfg.bool("verify_tls", False))


# --- parsing helpers -------------------------------------------------------


def mac(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower().replace("-", ":")
    return v if MAC.match(v) and v != "00:00:00:00:00:00" else None


def number(value: Any) -> float | None:
    """'1.2 ms' → 1.2, '0.0 %' → 0.0, '~' → None."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        m = re.search(r"-?\d+(\.\d+)?", value)
        if m:
            return float(m.group())
    return None


def counter(value: Any) -> int | None:
    n = number(value)
    return int(n) if n is not None and n >= 0 else None


def speed_from_media(media: str) -> int | None:
    """'1000baseT <full-duplex>' → 1000, '2500Base-T' → 2500, '10Gbase-T' → 10000."""
    m = re.search(r"(\d+(?:\.\d+)?)\s*(G)?base", media, re.IGNORECASE)
    if not m:
        return None
    value = float(m.group(1))
    return int(value * 1000) if m.group(2) else int(value)


def speed_from_rate(rate: Any) -> int | None:
    """'1000000000 bit/s' → 1000."""
    bits = number(rate)
    return int(bits // 1_000_000) if bits else None


def uptime_seconds(text: Any) -> int | None:
    """'3 days, 04:12:09' or '04:12:09' (the word "days" may be translated)."""
    if not isinstance(text, str):
        return None
    m = re.search(r"(?:(\d+)\D+)?(\d+):(\d{2}):(\d{2})\s*$", text.strip())
    if not m:
        return None
    days, h, mi, s = (int(x) if x else 0 for x in m.groups())
    return ((days * 24 + h) * 60 + mi) * 60 + s


# NICs of a hypervisor (OPNsense running as a VM): no physical jack.
VIRTUAL_NIC = re.compile(r"^(vtnet|xn|hn|vmx|em_virt)\d")
COPPER = re.compile(r"base-?T", re.IGNORECASE)  # 1000baseT, 2500Base-T, 10Gbase-T, 100baseTX
FIBER_OR_DAC = re.compile(
    r"base-?(SR|LR|ER|ZR|LRM|SX|LX|ZX|BX|CX|CR|KR|Twinax|AOC|SFI)", re.IGNORECASE
)


def interface_type(device: str, row: dict[str, Any] | None = None) -> str:
    row = row or {}
    if row.get("vlan") or re.match(r"^(vlan\d|.*_vlan\d|\w+\.\d+$)", device):
        return "vlan"
    if device.startswith(("lagg", "lag")):
        return "lag"
    if device.startswith("bridge"):
        return "bridge"
    if device.startswith(
        (
            "wg",
            "ovpn",
            "tun",
            "tap",
            "gif",
            "gre",
            "ipsec",
            "tailscale",
            "ppp",
            "pppoe",
            "l2tp",
            "zt",
        )
    ):
        return "tunnel"
    if device.startswith(("ath", "iwm", "iwn", "wlan", "iwlwifi")):
        return "wireless"
    if VIRTUAL_NIC.match(device):
        return "other"
    return "ethernet"


def connector(row: dict[str, Any], speed: int | None) -> str | None:
    """RJ45 or SFP, from the current media; when the port is down, from the
    media it supports (only if they all agree: some drivers list everything)."""
    media = (row.get("media") or "").strip()
    kinds = []
    if media and media != "autoselect":
        kinds = [media]
    else:
        kinds = [m for m in row.get("supported_media") or [] if m.strip() != "autoselect"]
    copper = any(COPPER.search(m) and not FIBER_OR_DAC.search(m) for m in kinds)
    fiber = any(FIBER_OR_DAC.search(m) for m in kinds)
    if copper == fiber:  # nothing known, or mixed
        return None
    if copper:
        return "rj45"
    return "qsfp" if speed and speed >= 40_000 else "sfp"


def optional(what: str, missing: list[str], fn: Callable[[], T], default: T) -> T:
    """Optional data: a missing privilege or feature never fails the collection."""
    try:
        return fn()
    except Forbidden:
        log.warning("no privilege for %s (%s)", what, PRIVILEGES.get(what, what))
        missing.append(PRIVILEGES.get(what, what))
    except NotFound:
        log.info("%s not available on this OPNsense", what)
    except PluginError:
        raise
    except Exception:
        log.exception("could not read %s", what)
    return default


# --- readers ---------------------------------------------------------------


def system_information(c: Client) -> dict[str, Any]:
    try:
        return c.get(
            "/api/diagnostics/system/system_information",
            "/api/diagnostics/system/systemInformation",
        )
    except Forbidden as e:
        raise PluginError(
            "connected, but the API user cannot read the dashboard: "
            f"give it the privilege {PRIVILEGES['system']}"
        ) from e
    except NotFound as e:
        raise PluginError(f"{c.base} does not look like OPNsense (no system API)") from e


def interfaces(c: Client) -> tuple[list[Interface], dict[str, str], dict[str, str]]:
    """Ports; logical name → device (lan → igb1); gateway address → device."""
    data = c.get(
        "/api/interfaces/overview/interfaces_info/1", "/api/interfaces/overview/interfacesInfo/1"
    )
    rows = [r for r in data.get("rows", []) if r.get("device") and not SKIP.match(r["device"])]
    by_device = {r["device"]: r for r in rows}
    out: list[Interface] = []
    logical: dict[str, str] = {}
    via: dict[str, str] = {}
    for row in rows:
        device = row["device"]
        if row.get("identifier"):
            logical[row["identifier"]] = device
        for address in row.get("gateways") or []:
            via[str(address)] = device
        stats = row.get("statistics") or {}
        kind = interface_type(device, row)
        media = (row.get("media") or "").strip()
        up = row.get("status") == "up"
        speed = speed_from_media(media) or speed_from_rate(stats.get("line rate"))
        if kind in ("other", "tunnel"):
            speed = None  # a virtual NIC reports a made-up speed
        if kind == "bridge":
            speed = bridge_speed(row, by_device)
        duplex = "full" if "full-duplex" in media else "half" if "half-duplex" in media else None
        wan = is_wan(row)
        parent = (row.get("vlan") or {}).get("parent")
        if wan and not parent and kind == "tunnel":
            parent = carrier(rows)  # PPPoE: the port it runs on
        if wan and not speed and parent:
            speed = link_speed(parent, by_device)
        ips = [a["ipaddr"] for a in row.get("ipv4") or [] if a.get("ipaddr")]
        ips += [
            a["ipaddr"]
            for a in row.get("ipv6") or []
            if a.get("ipaddr") and not a["ipaddr"].lower().startswith("fe80")
        ]
        description = row.get("description")
        if description == "Unassigned Interface":
            description = None
        out.append(
            Interface(
                name=device,
                description=description or None,
                type=kind,
                connector=connector(row, speed) if kind in ("ethernet", "lag") else None,
                mac=mac(row.get("macaddr_hw") or row.get("macaddr")),
                up=up,
                speed_mbps=speed if up and speed else None,
                duplex=duplex if kind not in ("other", "tunnel", "bridge") else None,
                media=media or None,
                ips=ips or None,
                wan=True if wan else None,
                parent=parent or None,
                rx_bytes=counter(stats.get("bytes received")),
                tx_bytes=counter(stats.get("bytes transmitted")),
                rx_errors=counter(stats.get("input errors")),
                tx_errors=counter(stats.get("output errors")),
            )
        )
    return out, logical, via


def bridge_speed(row: dict[str, Any], by_device: dict[str, dict[str, Any]]) -> int | None:
    """A bridge (e.g. the LAN joining a 10G port and a VM's NIC) runs at the
    speed of its fastest physical member; virtual NICs do not count."""
    speeds = [
        speed_from_media((by_device.get(m) or {}).get("media") or "")
        for m in (row.get("members") or {})
        if interface_type(m, by_device.get(m)) == "ethernet"
    ]
    return max((s for s in speeds if s), default=None)


def is_wan(row: dict[str, Any]) -> bool:
    """An interface with upstream gateways (OPNsense lists them per interface)."""
    return bool(row.get("gateways")) or str(row.get("identifier", "")).startswith("wan")


def carrier(rows: list[dict[str, Any]]) -> str | None:
    """The port a PPPoE/PPP WAN runs on. OPNsense does not expose it in this
    API; the usual setup is a VLAN with no role assigned (e.g. vlan0.2000 for
    an ISP that tags PPPoE), else a port whose description says WAN."""
    vlans = [r for r in rows if r.get("vlan") and not r.get("identifier")]
    if len(vlans) == 1:
        return vlans[0]["device"]
    named = [
        r["device"]
        for r in rows
        if "wan" in str(r.get("description", "")).lower()
        and interface_type(r["device"], r) == "ethernet"
    ]
    return named[0] if len(named) == 1 else None


def link_speed(device: str, by_device: dict[str, dict[str, Any]]) -> int | None:
    """Speed of a port, following VLANs down to the physical port."""
    for _ in range(4):
        row = by_device.get(device)
        if not row:
            return None
        speed = speed_from_media((row.get("media") or "").strip())
        if speed:
            return speed
        device = (row.get("vlan") or {}).get("parent")
        if not device:
            return None
    return None


def traffic(c: Client, ifaces: list[Interface]) -> None:
    """Fills counters missing from the interface overview."""
    if all(i.rx_bytes is not None for i in ifaces):
        return
    data = c.get("/api/diagnostics/traffic/interface")
    by_device = {v.get("device"): v for v in (data.get("interfaces") or {}).values()}
    for i in ifaces:
        s = by_device.get(i.name)
        if s and i.rx_bytes is None:
            i.rx_bytes = counter(s.get("bytes received"))
            i.tx_bytes = counter(s.get("bytes transmitted"))
            i.rx_errors = counter(s.get("input errors"))
            i.tx_errors = counter(s.get("output errors"))


def arp(c: Client) -> list[ArpEntry]:
    data = c.get("/api/diagnostics/interface/search_arp", params={"rowCount": -1})
    out = []
    for row in data.get("rows", []):
        m = mac(row.get("mac"))
        if not m or row.get("permanent") or row.get("expired") or not row.get("ip"):
            continue
        out.append(ArpEntry(ip=row["ip"], mac=m, interface=row.get("intf") or None))
    return out


def leases(c: Client, missing: list[str]) -> list[DhcpLease]:
    """Leases of every DHCP server in use (ISC, Kea, dnsmasq), merged."""
    now = time.time()
    found: dict[tuple[str, str], DhcpLease] = {}
    forbidden = 0

    def add(ip: Any, hw: Any, host: Any, expires: float | None = None) -> None:
        m = mac(hw)
        if not m or not isinstance(ip, str) or not ip or ":" in ip:  # IPv4 leases
            return
        name = host if isinstance(host, str) and host not in ("", "*") else None
        at = (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires))
            if expires and expires > 0
            else None
        )
        found[(ip, m)] = DhcpLease(ip=ip, mac=m, hostname=name, expires_at=at)

    sources = [
        ("/api/dhcpv4/leases/search_lease", {"inactive": 0, "rowCount": -1}),
        ("/api/kea/leases4/search", {"rowCount": -1}),
        ("/api/dnsmasq/leases/search", {"rowCount": -1}),
    ]
    for path, params in sources:
        try:
            rows = c.get(path, params=params).get("rows", [])
        except Forbidden:
            forbidden += 1
            continue
        except NotFound:
            continue
        for r in rows:
            if "binding" in r or "starts" in r:  # ISC
                if r.get("state") not in (None, "active", "static") and r.get("type") != "static":
                    continue
                add(r.get("address"), r.get("mac"), r.get("hostname"))
            elif "state" in r and "valid_lifetime" in r:  # Kea memfile
                expire = number(r.get("expire"))
                if str(r.get("state")) != "0" or (expire and expire < now):
                    continue
                add(r.get("address"), r.get("hwaddr"), r.get("hostname"), expire)
            else:  # dnsmasq (expire 0 = never)
                expire = number(r.get("expire"))
                if expire and expire < now:
                    continue
                add(r.get("address"), r.get("hwaddr"), r.get("hostname"), expire)
    if forbidden == len(sources):
        missing.append(PRIVILEGES["dhcp"])
    return sorted(found.values(), key=lambda lease: tuple(int(p) for p in lease.ip.split(".")))


GATEWAY_STATUS = {
    "none": "up",
    "down": "down",
    "force_down": "down",
    "delay": "degraded",
    "loss": "degraded",
    "delay+loss": "degraded",
}


def gateways(c: Client, via: dict[str, str] | None = None) -> list[Gateway]:
    """via: gateway address → interface (from the interfaces' gateway lists)."""
    data = c.get("/api/routes/gateway/status")
    out = []
    for g in data.get("items", []):
        if not g.get("name"):
            continue
        no_data = g.get("delay") == "~"
        status = "unknown" if no_data else GATEWAY_STATUS.get(g.get("status", ""), "unknown")
        address = g.get("address")
        out.append(
            Gateway(
                name=g["name"],
                address=address if address and address != "~" else None,
                interface=(via or {}).get(address or "") or (via or {}).get(g.get("monitor") or ""),
                status=status,
                rtt_ms=None if no_data else number(g.get("delay")),
                loss_pct=None if no_data else number(g.get("loss")),
            )
        )
    return out


def memory_pct(c: Client) -> float | None:
    data = c.get(
        "/api/diagnostics/system/system_resources", "/api/diagnostics/system/systemResources"
    )
    mem = data.get("memory") or {}
    total, used = number(mem.get("total")), number(mem.get("used"))
    if not total or used is None:
        return None
    return round(used / total * 100, 1)


def uptime(c: Client) -> int | None:
    data = c.get("/api/diagnostics/system/system_time", "/api/diagnostics/system/systemTime")
    return uptime_seconds(data.get("uptime"))


def cpu_pct(c: Client) -> float | None:
    event = c.stream_second_event("/api/diagnostics/cpu_usage/stream")
    if not event:
        return None
    total = number(event.get("total"))
    if total is None and number(event.get("idle")) is not None:
        total = 100 - number(event.get("idle"))
    return total


# --- plugin entry points -------------------------------------------------------


def collect(cfg: Config) -> list[Device]:
    c = client_from(cfg)
    try:
        info = system_information(c)
        missing: list[str] = []
        ifaces, _logical, via = optional("interfaces", missing, lambda: interfaces(c), ([], {}, {}))
        optional("traffic", missing, lambda: traffic(c, ifaces), None)
        versions = info.get("versions") or []
        os_version = versions[0].rsplit("-", 1)[0] if versions else None
        macs = sorted({i.mac for i in ifaces if i.mac})
        lan_mac = next((i.mac for i in ifaces if i.mac and i.description == "LAN"), None)
        ips = sorted({ip.split("/")[0] for i in ifaces for ip in (i.ips or []) if "." in ip})
        host = urlparse(c.base).hostname or c.base
        device = Device(
            key=lan_mac or (macs[0] if macs else host),
            name=info.get("name") or host,
            host=host,
            role="firewall",
            vendor="OPNsense",
            os_version=os_version,
            uptime_s=optional("system", missing, lambda: uptime(c), None),
            cpu_pct=optional("system", missing, lambda: cpu_pct(c), None),
            mem_pct=optional("system", missing, lambda: memory_pct(c), None),
            macs=macs or None,
            ips=ips or None,
            interfaces=ifaces or None,
            arp=optional("arp", missing, lambda: arp(c), []) or None,
            dhcp_leases=leases(c, missing) or None,
            gateways=optional("gateways", missing, lambda: gateways(c, via), []) or None,
        )
        if missing:
            log.warning("missing privileges: %s", ", ".join(sorted(set(missing))))
        return [device]
    finally:
        c.close()


def test(cfg: Config) -> str:
    c = client_from(cfg)
    try:
        info = system_information(c)
        missing: list[str] = []
        optional("interfaces", missing, lambda: interfaces(c), None)
        optional("arp", missing, lambda: arp(c), None)
        leases(c, missing)
        optional("gateways", missing, lambda: gateways(c), None)
        versions = info.get("versions") or []
        version = versions[0].rsplit("-", 1)[0] if versions else "OPNsense"
        msg = f"Connected to {info.get('name') or c.base} ({version})"
        if missing:
            msg += ". Missing privileges: " + "; ".join(sorted(set(missing)))
        return msg
    finally:
        c.close()
