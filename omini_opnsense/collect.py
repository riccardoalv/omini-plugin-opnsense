"""Turns OPNsense API answers into Omini devices."""

from __future__ import annotations

import ipaddress
import math
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
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

try:  # system health, in the SDK of Omini 0.2 and later
    from omini_sdk import Firmware, Storage, Temperature

    HEALTH = True
except ImportError:  # an older Omini: the plugin still works, without them
    HEALTH = False

try:  # services, VPN peers, VLANs, DHCP pools, firewall states: Omini 0.3 and later
    from omini_sdk import DhcpPool, FirewallStates, Service, Transceiver, Vlan, VpnPeer

    EXTRAS = True
except ImportError:
    EXTRAS = False

try:  # paused devices: Omini 1.3 and later
    from omini_sdk.models import PausedDevice
except ImportError:
    PausedDevice = None  # type: ignore[assignment,misc]

try:  # backups: Omini 1.3 and later
    from omini_sdk import ConfigBackup
except ImportError:
    ConfigBackup = None

from omini_opnsense import backup as backups
from omini_opnsense import dns, pause
from omini_opnsense import networks as nets
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
    "firmware": "System: Firmware",
    "services": "Status: Services",
    "vlans": "Interfaces: VLAN",
    "networks": (
        "Interfaces: Assignments, Interfaces: VLAN, Services: Kea DHCP (or Dnsmasq), "
        "Firewall: Rules, Firewall: Alias"
    ),
    "states": "Diagnostics: Firewall statistics",
    "lagg": "Interfaces: LAGG",
    "dns": "Services: Unbound DNS: Edit Host and Domain Override (or Services: Dnsmasq DNS/DHCP)",
    "pause": "Firewall: Alias, Firewall: Rules, Interfaces: Assignments, Interfaces: VLAN",
    "wol": "Services: Wake on LAN",
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


def interfaces(
    c: Client, vlan_config: dict[str, dict[str, Any]] | None = None
) -> tuple[list[Interface], dict[str, str], dict[str, str]]:
    """Ports; logical name → device (lan → igb1); gateway address → device.
    vlan_config: VLAN device → {tag, parent, name}, from Interfaces → Devices → VLAN."""
    vlan_config = vlan_config or {}
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
            # Dynamic gateways are named after the interface: WAN_PPPOE, WAN_DHCP.
            if row.get("description"):
                via["descr:" + str(row["description"]).upper()] = device
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
        configured = vlan_config.get(device) or {}
        parent = (row.get("vlan") or {}).get("parent") or configured.get("parent")
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
                connector=(connector(row, speed) or plugged_connector(row.get("sfp")))
                if kind in ("ethernet", "lag")
                else None,
                mac=mac(row.get("macaddr_hw") or row.get("macaddr")),
                up=up,
                speed_mbps=speed if up and speed else None,
                duplex=duplex if kind not in ("other", "tunnel", "bridge") else None,
                media=media or None,
                ips=ips or None,
                wan=True if wan else None,
                parent=parent or None,
                **members_of(row, kind),
                **newer_fields(
                    Interface,
                    vlan=vlan_tag(device, row, configured) if kind == "vlan" else None,
                    transceiver=transceiver(row.get("sfp")) if kind == "ethernet" else None,
                ),
                rx_bytes=counter(stats.get("bytes received")),
                tx_bytes=counter(stats.get("bytes transmitted")),
                rx_errors=counter(stats.get("input errors")),
                tx_errors=counter(stats.get("output errors")),
            )
        )
    return out, logical, via


def members_of(row: dict[str, Any], kind: str) -> dict[str, Any]:
    """A bridge's or a link aggregation's ports (``members``, in the SDK of
    Omini 0.2.1 and later)."""
    if "members" not in Interface.model_fields:
        return {}
    if kind == "bridge":
        names = sorted(row.get("members") or {})
    elif kind == "lag":
        names = sorted(row.get("laggport") or {})
    else:
        return {}
    return {"members": names} if names else {}


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
    API; the port carries no role of its own (it is not assigned): a VLAN
    (e.g. vlan0.2000 for an ISP that tags PPPoE), else the one physical port
    that is up, unassigned and not part of a link aggregation, else an
    unassigned port whose description says WAN."""
    unassigned = [r for r in rows if not r.get("identifier")]
    vlans = [r for r in unassigned if r.get("vlan")]
    if len(vlans) == 1:
        return vlans[0]["device"]
    in_lagg = {m for r in rows for m in (r.get("laggport") or {})}
    ports = [
        r["device"]
        for r in unassigned
        if interface_type(r["device"], r) == "ethernet"
        and r.get("status") == "up"
        and r["device"] not in in_lagg
    ]
    if len(ports) == 1:
        return ports[0]
    named = [
        r["device"]
        for r in unassigned
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


def ndp(c: Client) -> list[ArpEntry]:
    """IPv6 neighbours, so flows over IPv6 reach the device's MAC. Extra data:
    an error reading it leaves it out instead of failing the collection."""
    try:
        rows = pause.ndp_rows(c)
    except PluginError as e:
        log.info("could not read the NDP table: %s", e)
        return []
    out = []
    for row in rows:
        m, ip = mac(row.get("mac")), str(row.get("ip") or "").strip().lower()
        if m and ip:
            out.append(ArpEntry(ip=ip, mac=m, interface=row.get("intf") or None))
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


# Suffixes OPNsense gives the gateways it creates for an interface.
GATEWAY_PROTOCOLS = (
    "DHCP",
    "DHCP6",
    "PPPOE",
    "PPP",
    "PPTP",
    "L2TP",
    "SLAAC",
    "TRACK6",
    "6RD",
    "6TO4",
    "GW",
    "GWV6",
)


def gateway_interface(g: dict[str, Any], via: dict[str, str]) -> str | None:
    """The interface a gateway is on: by its address or monitor IP (in the
    interfaces' gateway lists), else by its name — a dynamic gateway is named
    after its interface (WAN_PPPOE), which keeps it tied to a dial-up link
    that is down and has no address."""
    for key in (g.get("address"), g.get("monitor")):
        if key and key != "~" and via.get(str(key)):
            return via[str(key)]
    base, _, proto = str(g.get("name") or "").upper().rpartition("_")
    if base and proto in GATEWAY_PROTOCOLS:
        return via.get("descr:" + base)
    return None


def gateways(c: Client, via: dict[str, str] | None = None) -> list[Gateway]:
    """via: gateway address → interface (from the interfaces' gateway lists)."""
    data = c.get("/api/routes/gateway/status")
    out = []
    for g in data.get("items", []):
        if not g.get("name"):
            continue
        no_data = g.get("delay") == "~"
        status = GATEWAY_STATUS.get(g.get("status", ""), "unknown")
        if no_data and status != "down":
            # Not measured yet ("Pending"); a gateway that is down has no
            # delay to measure, and is down all the same.
            status = "unknown"

        address = g.get("address")
        out.append(
            Gateway(
                name=g["name"],
                address=address if address and address != "~" else None,
                interface=gateway_interface(g, via or {}),
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


def system_time(c: Client) -> dict[str, Any]:
    """Uptime and load average."""
    return c.get("/api/diagnostics/system/system_time", "/api/diagnostics/system/systemTime")


def load_avg(text: Any) -> list[float] | None:
    """'0.34, 0.35, 0.33' → [0.34, 0.35, 0.33] (1, 5 and 15 minutes)."""
    if not isinstance(text, str):
        return None
    values = [number(v) for v in re.split(r"[,\s]+", text.strip()) if v]
    values = [v for v in values if v is not None and v >= 0]
    return values[:3] or None


def swap_pct(c: Client) -> float | None:
    data = c.get("/api/diagnostics/system/system_swap", "/api/diagnostics/system/systemSwap")
    rows = data.get("swap") or []
    total = sum(number(r.get("total")) or 0 for r in rows)
    used = sum(number(r.get("used")) or 0 for r in rows)
    return round(used / total * 100, 1) if total else None


def storage(c: Client) -> list[Storage]:
    """Mounted file systems. ZFS datasets share their pool's space, so each
    pool is one entry (named after its mount closest to /) with the pool's use."""
    data = c.get("/api/diagnostics/system/system_disk", "/api/diagnostics/system/systemDisk")
    out: list[Storage] = []
    pools: dict[str, dict[str, Any]] = {}
    for row in data.get("devices") or []:
        mount = row.get("mountpoint")
        total = number(row.get("total_bytes"))
        used = number(row.get("used_bytes")) or 0
        if not mount or not total:
            continue
        if row.get("type") == "zfs":
            name = str(row.get("device") or "").split("/")[0]
            pool = pools.setdefault(
                name, {"mounts": [], "used": 0, "free": number(row.get("available_bytes")) or 0}
            )
            pool["mounts"].append(mount)
            pool["used"] += used
            continue
        out.append(
            Storage(
                mount=mount,
                device=row.get("device") or None,
                fs_type=row.get("type") or None,
                total_bytes=int(total),
                used_bytes=int(used),
            )
        )
    for name, pool in pools.items():
        mount = min(pool["mounts"], key=lambda m: (m.count("/") if m != "/" else 0, len(m)))
        out.append(
            Storage(
                mount=mount,
                device=name,
                fs_type="zfs",
                total_bytes=int(pool["used"] + pool["free"]),
                used_bytes=int(pool["used"]),
            )
        )
    return sorted(out, key=lambda st: (st.mount != "/", st.mount))


def temperature_kind(device: str) -> str:
    if device.startswith(("dev.cpu", "hw.acpi.thermal.cpu")):
        return "cpu"
    if re.match(r"^(ada|da|nvme|nvd)\d", device) or "smart" in device:
        return "disk"
    if "acpi" in device or "thermal" in device or "pch" in device:
        return "board"
    return "other"


def temperatures(c: Client) -> list[Temperature]:
    """Sensors OPNsense reads (none on most virtual machines)."""
    data = c.get(
        "/api/diagnostics/system/system_temperature",
        "/api/diagnostics/system/systemTemperature",
    )
    rows = data if isinstance(data, list) else data.get("rows") or []
    out = []
    for row in rows:
        celsius = number(row.get("temperature"))
        device = str(row.get("device") or "")
        if celsius is None or not device:
            continue
        kind = temperature_kind(device)
        seq = row.get("device_seq")
        name = row.get("type_translated") or row.get("type") or device
        if kind == "cpu" and seq not in (None, ""):
            name = f"CPU {seq}"
        out.append(Temperature(sensor=str(name), kind=kind, celsius=celsius))
    return out


def flag(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    return str(value).strip().lower() in ("1", "true", "yes")


def firmware(c: Client) -> Firmware | None:
    """What the firewall knows from its last update check. Omini never starts
    a check itself (read-only); OPNsense runs it from the GUI or its cron."""
    data = c.get("/api/core/firmware/status")
    product = data.get("product") or {}
    current = product.get("product_version") or None
    check = product.get("product_check") or {}
    latest = check.get("product_version") or product.get("product_latest") or None
    status = str(data.get("status") or "")
    if not check:
        # Never checked: only the installed version is known.
        return Firmware(current=current) if current else None
    count = number(check.get("updates"))
    if count is None:
        count = sum(
            len(check.get(k) or [])
            for k in ("new_packages", "upgrade_packages", "reinstall_packages")
        )
    available = status in ("update", "upgrade") or bool(count)
    checked = check.get("last_check")
    return Firmware(
        current=current,
        latest=latest,
        update_available=available,
        updates=int(count) if count is not None else None,
        needs_reboot=flag(check.get("upgrade_needs_reboot") or check.get("needs_reboot"))
        if available
        else None,
        checked_at=parse_time(checked),
    )


def parse_time(text: Any) -> str | None:
    """OPNsense dates ('Wed Oct 7 2:54:18 -04 2026', or ISO) → ISO 8601, with
    an offset (UTC when the date has none, as for 'UTC' or a naive ISO date)."""
    if not isinstance(text, str) or not text.strip():
        return None
    t = text.strip()
    for fmt in ("%a %b %d %H:%M:%S %z %Y", "%a %b %d %H:%M:%S %Z %Y"):
        try:
            v = re.sub(r" ([+-]\d{2})(?= \d{4}$)", r" \g<1>00", t)
            return aware(datetime.strptime(v, fmt)).isoformat()
        except ValueError:
            continue
    try:
        return aware(datetime.fromisoformat(t)).isoformat()
    except ValueError:
        return None


def aware(d: datetime) -> datetime:
    return d if d.tzinfo is not None else d.replace(tzinfo=timezone.utc)


def cpu_pct(c: Client) -> float | None:
    event = c.stream_second_event("/api/diagnostics/cpu_usage/stream")
    if not event:
        return None
    total = number(event.get("total"))
    if total is None and number(event.get("idle")) is not None:
        total = 100 - number(event.get("idle"))
    return total


def health(c: Client, clock: dict[str, Any], missing: list[str]) -> dict[str, Any]:
    """Load, swap, disks, temperatures and pending updates."""
    return {
        "swap_pct": optional("system", missing, lambda: swap_pct(c), None),
        "load_avg": load_avg(clock.get("loadavg")),
        "temperatures": optional("system", missing, lambda: temperatures(c), []) or None,
        "storage": optional("system", missing, lambda: storage(c), []) or None,
        "firmware": optional("firmware", missing, lambda: firmware(c), None),
    }


# --- VLANs, SFP modules, services, VPN, DHCP pools, firewall states ----------


def newer_fields(model: type, **values: Any) -> dict[str, Any]:
    """Fields an older SDK does not have are left out, so the plugin keeps
    working on an older Omini."""
    return {k: v for k, v in values.items() if v is not None and k in model.model_fields}


def first_word(value: Any) -> str | None:
    """'igb1 (00:0d:b9:aa:bb:cd) [LAN]' or 'vlan01 [IOT]' → 'igb1' / 'vlan01':
    OPNsense's searches show some fields with a description appended."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.split()[0]


def tag(value: Any) -> int | None:
    n = number(value)
    return int(n) if n is not None and 1 <= n <= 4094 else None


def vlan_config(c: Client) -> dict[str, dict[str, Any]]:
    """VLANs configured in Interfaces → Devices → VLAN, by device name."""
    data = c.get(
        "/api/interfaces/vlan_settings/search_item",
        "/api/interfaces/vlan_settings/searchItem",
        params={"rowCount": -1},
    )
    out: dict[str, dict[str, Any]] = {}
    for row in data.get("rows") or []:
        device, vid = first_word(row.get("vlanif")), tag(row.get("tag"))
        if not device or not vid:
            continue
        out[device] = {
            "tag": vid,
            "parent": first_word(row.get("if")),
            "name": (row.get("descr") or "").strip() or None,
        }
    return out


# Device names that carry the tag by construction: igb1_vlan20, igb1.20, vlan0.2000.
TAG_IN_NAME = re.compile(r"(?:_vlan|\.)(\d{1,4})$")


def vlan_tag(device: str, row: dict[str, Any], configured: dict[str, Any]) -> int | None:
    """The VLAN id of a VLAN interface: from ifconfig, the VLAN settings or its name."""
    vid = tag((row.get("vlan") or {}).get("tag")) or tag(row.get("vlan_tag"))
    if vid or configured.get("tag"):
        return vid or configured["tag"]
    m = TAG_IN_NAME.search(device)
    return tag(m.group(1)) if m else None


def vlans(ifaces: list[Interface], config: dict[str, dict[str, Any]]) -> list[Vlan]:
    """VLANs of the firewall: the configured ones, else the VLAN interfaces seen."""
    by_name = {i.name: i for i in ifaces}
    found: dict[str, dict[str, Any]] = {
        device: {"tag": v["tag"], "name": v["name"]} for device, v in config.items()
    }
    for i in ifaces:
        vid = getattr(i, "vlan", None)
        if i.type == "vlan" and vid and i.name not in found:
            found[i.name] = {"tag": vid, "name": None}
    out = []
    for device, v in found.items():
        iface = by_name.get(device)
        name = v["name"] or (iface.description if iface else None)
        out.append(
            Vlan(
                id=v["tag"], name=name, interface=device, subnet=subnet_of(iface) if iface else None
            )
        )
    return sorted(out, key=lambda vl: (vl.id, vl.interface or ""))


def subnet_of(iface: Interface) -> str | None:
    for ip in iface.ips or []:
        try:
            net = ipaddress.ip_interface(ip).network
        except ValueError:
            continue
        if net.version == 4 and "/" in ip:
            return str(net)
    return None


def dbm(value: Any) -> float | None:
    """'0.55 mW (-2.59 dBm)' → -2.59; '0.55 mW' → -2.6."""
    if not isinstance(value, str):
        return None
    m = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", value)
    if m:
        return float(m.group(1))
    mw = number(value)
    if mw is None or mw <= 0 or "mw" not in value.lower():
        return None
    return round(10 * math.log10(mw), 2)


def plugged_connector(sfp: Any) -> str | None:
    """The cage of a port with a module plugged in ('SFP/SFP+/SFP28 ...', 'QSFP+ ...')."""
    plugged = str((sfp or {}).get("plugged") or "") if isinstance(sfp, dict) else ""
    if plugged.upper().startswith("QSFP"):
        return "qsfp"
    if plugged.upper().startswith("SFP"):
        return "sfp"
    return None


def transceiver(sfp: Any) -> Transceiver | None:
    """The module in a port, as OPNsense reads it from ``ifconfig -v`` (only
    drivers that can read the module's EEPROM report it). ``plugged`` is
    '<class> <compliance> (<connector>)', e.g. 'SFP/SFP+/SFP28 10G Base-SR (LC)'."""
    if not EXTRAS or not isinstance(sfp, dict) or not sfp.get("plugged"):
        return None
    plugged = str(sfp["plugged"]).strip()
    m = re.match(r"^\S+\s+(.*?)\s*(?:\([^)]*\))?$", plugged)
    kind = (m.group(1) if m else "") or None
    lanes = sorted(
        {int(k.split("_")[1]) for k in sfp if re.match(r"^lane_\d+_rx_power$", k)},
    )
    rx = [(dbm(sfp.get(f"lane_{n}_rx_power")), n) for n in lanes]
    rx = [(p, n) for p, n in rx if p is not None]
    weakest = min(rx) if rx else None  # the weakest lane is the one that matters

    def text(key: str) -> str | None:
        v = sfp.get(key)
        return (v.strip() or None) if isinstance(v, str) else None

    return Transceiver(
        vendor=text("vendor"),
        part=text("part_number"),
        serial=text("serial_number"),
        type=kind,
        temperature_c=number(sfp.get("temperature")),
        voltage_v=number(sfp.get("voltage")),
        rx_power_dbm=weakest[0] if weakest else None,
        bias_ma=number(sfp.get(f"lane_{weakest[1]}_tx_bias")) if weakest else None,
    )


def services(c: Client) -> list[Service]:
    """Services in System → Diagnostics → Services. OPNsense lists only the
    services that are enabled in its configuration, so each one is enabled."""
    data = c.get("/api/core/service/search", params={"rowCount": -1})
    out = []
    for row in data.get("rows") or []:
        name = row.get("id") or row.get("name")
        if not name:
            continue
        out.append(
            Service(
                name=str(name),
                description=row.get("description") or None,
                running=flag(row.get("running")),
                enabled=True,
            )
        )
    return sorted(out, key=lambda s: s.name)


def epoch(value: Any) -> str | None:
    n = number(value)
    if not n or n <= 0:
        return None
    return datetime.fromtimestamp(n, tz=timezone.utc).isoformat()


def wireguard_peers(c: Client) -> list[VpnPeer]:
    """Peers from `wg show all dump` (VPN → WireGuard → Status)."""
    data = c.get("/api/wireguard/service/show", params={"rowCount": -1})
    out = []
    for r in data.get("rows") or []:
        if r.get("type") != "peer":
            continue
        key = str(r.get("public-key") or "")
        name = r.get("name") or f"{r.get('ifname') or r.get('if') or 'wg'} {key[:8]}".strip()
        endpoint = r.get("endpoint")
        out.append(
            VpnPeer(
                name=name,
                protocol="wireguard",
                endpoint=endpoint if endpoint and endpoint != "(none)" else None,
                address=r.get("allowed-ips") or None,
                # OPNsense calls a peer online after a handshake in the last 5 minutes.
                connected=r.get("peer-status") == "online",
                last_handshake=epoch(r.get("latest-handshake")),
                rx_bytes=counter(r.get("transfer-rx")),
                tx_bytes=counter(r.get("transfer-tx")),
            )
        )
    return out


def openvpn_peers(c: Client) -> list[VpnPeer]:
    """Clients connected to each OpenVPN server and the firewall's own OpenVPN
    clients (VPN → OpenVPN → Connection Status)."""
    data = c.get(
        "/api/openvpn/service/search_sessions",
        "/api/openvpn/service/searchSessions",
        params={"rowCount": -1},
    )
    out = []
    for r in data.get("rows") or []:
        connected_client = bool(r.get("is_client"))
        if r.get("type") == "server" and not connected_client and r.get("status") != "connected":
            continue  # a server waiting for clients is not a peer (p2p ones are)
        name = r.get("common_name") if connected_client else None
        name = name or r.get("description") or f"OpenVPN {r.get('id')}"
        endpoint = r.get("real_address") or None
        up = connected_client or r.get("status") == "connected"
        out.append(
            VpnPeer(
                name=str(name),
                protocol="openvpn",
                endpoint=endpoint,
                address=r.get("virtual_address") or None,
                connected=up,
                rx_bytes=counter(r.get("bytes_received")) if up else None,
                tx_bytes=counter(r.get("bytes_sent")) if up else None,
            )
        )
    return out


def ipsec_peers(c: Client) -> list[VpnPeer]:
    """IPsec tunnels (phase 1), with the traffic of their child SAs."""
    data = c.get(
        "/api/ipsec/sessions/search_phase1",
        "/api/ipsec/sessions/searchPhase1",
        params={"rowCount": -1},
    )
    out = []
    for r in data.get("rows") or []:
        name = r.get("phase1desc") or r.get("name")
        if not name:
            continue
        remote = str(r.get("remote-addrs") or "")
        up = bool(r.get("connected"))
        out.append(
            VpnPeer(
                name=str(name),
                protocol="ipsec",
                endpoint=remote if remote and remote not in ("%any", "0.0.0.0", "::") else None,
                connected=up,
                rx_bytes=counter(r.get("bytes-in")) if up else None,
                tx_bytes=counter(r.get("bytes-out")) if up else None,
            )
        )
    return out


def quiet(what: str, fn: Callable[[], T], default: T) -> T:
    """Data only some firewalls have (a VPN, a DHCP server): its privilege is
    only needed by those who use it, so a refusal is not a missing privilege."""
    try:
        return fn()
    except Forbidden:
        log.info("no privilege for %s", what)
    except NotFound:
        log.info("%s not available on this OPNsense", what)
    except PluginError:
        raise
    except Exception:
        log.exception("could not read %s", what)
    return default


def vpn_peers(c: Client) -> list[VpnPeer]:
    """Every VPN in use; one nobody configured answers with no rows."""
    return [
        *quiet("the WireGuard status", lambda: wireguard_peers(c), []),
        *quiet("the OpenVPN status", lambda: openvpn_peers(c), []),
        *quiet("the IPsec status", lambda: ipsec_peers(c), []),
    ]


def firewall_states(c: Client) -> FirewallStates | None:
    """Size of pf's state table (`pfctl -si`) and its hard limit (`pfctl -sm`)."""
    info = c.get(
        "/api/diagnostics/firewall/pf_statistics/info",
        "/api/diagnostics/firewall/pfStatistics/info",
    )
    table = ((info or {}).get("info") or {}).get("state-table") or {}
    current = counter((table.get("current-entries") or {}).get("total"))
    limit = None
    try:
        memory = c.get(
            "/api/diagnostics/firewall/pf_statistics/memory",
            "/api/diagnostics/firewall/pfStatistics/memory",
        )
        limit = counter(((memory or {}).get("memory") or {}).get("states"))
    except NotFound:
        pass
    if current is None and limit is None:
        return None
    return FirewallStates(current=current, limit=limit)


Range = tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]


def ip_range(text: Any) -> Range | None:
    """'192.168.1.100 - 192.168.1.199' or '192.168.1.128/26' (IPv4 only)."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        if "-" in text:
            a, b = (ipaddress.IPv4Address(p.strip()) for p in text.split("-", 1))
        else:
            net = ipaddress.IPv4Network(text.strip(), strict=False)
            a, b = net.network_address, net.broadcast_address
    except ValueError:
        return None
    return (a, b) if a <= b else None


def kea_ranges(c: Client) -> dict[str, list[Range]]:
    """Pools of each Kea subnet (Services → Kea DHCP → Kea DHCPv4 → Subnets)."""
    data = c.get(
        "/api/kea/dhcpv4/search_subnet", "/api/kea/dhcpv4/searchSubnet", params={"rowCount": -1}
    )
    out: dict[str, list[Range]] = {}
    for row in data.get("rows") or []:
        subnet = row.get("subnet")
        if not subnet or ":" in str(subnet):
            continue
        pools = [ip_range(p) for p in re.split(r"[\n,]", str(row.get("pools") or ""))]
        pools = [p for p in pools if p]
        if pools:
            out.setdefault(str(subnet), []).extend(pools)
    return out


def dnsmasq_ranges(c: Client, ifaces: list[Interface]) -> dict[str, list[Range]]:
    """DHCP ranges of dnsmasq (Services → Dnsmasq DNS & DHCP → DHCP ranges),
    named after the subnet of the interface that holds them."""
    data = c.get(
        "/api/dnsmasq/settings/search_range",
        "/api/dnsmasq/settings/searchRange",
        params={"rowCount": -1},
    )
    nets = [
        ipaddress.ip_interface(ip).network
        for i in ifaces
        for ip in i.ips or []
        if "." in ip and "/" in ip
    ]
    out: dict[str, list[Range]] = {}
    for row in data.get("rows") or []:
        start, end = row.get("start_addr"), row.get("end_addr")
        if not start or not end:
            continue  # an IPv6 constructor or a static-only range
        r = ip_range(f"{start}-{end}")
        if not r:
            continue
        net = next((n for n in nets if r[0] in n), None)
        name = str(net) if net else (row.get("%interface") or row.get("interface") or None)
        out.setdefault(name or f"{start}-{end}", []).append(r)
    return out


def dhcp_pools(c: Client, ifaces: list[Interface], active: list[DhcpLease]) -> list[DhcpPool]:
    """Usage of each DHCP range: its addresses and the active leases in it.
    ISC DHCP keeps its ranges outside the API, so only Kea and dnsmasq count."""
    ranges: dict[str, list[Range]] = {}
    for what, read in (
        ("the Kea subnets", lambda: kea_ranges(c)),
        ("the dnsmasq DHCP ranges", lambda: dnsmasq_ranges(c, ifaces)),
    ):
        for network, found in quiet(what, read, {}).items():
            ranges.setdefault(network, []).extend(found)
    leased = {ipaddress.IPv4Address(lease.ip) for lease in active}
    out = []
    for network, rs in ranges.items():
        total = sum(int(b) - int(a) + 1 for a, b in rs)
        used = sum(1 for ip in leased if any(a <= ip <= b for a, b in rs))
        out.append(DhcpPool(network=network, total=total, used=used))
    return sorted(out, key=lambda p: p.network)


def lagg_config(c: Client) -> dict[str, list[str]]:
    """Link aggregations of Interfaces → Devices → LAGG: lagg0 → its member ports
    (also those that are down, which the interface overview leaves out)."""
    data = c.get(
        "/api/interfaces/lagg_settings/search_item",
        "/api/interfaces/lagg_settings/searchItem",
        params={"rowCount": -1},
    )
    out: dict[str, list[str]] = {}
    for row in data.get("rows") or []:
        lagg = first_word(row.get("laggif"))
        members = [first_word(m) for m in re.split(r"[,\n]", text_of(row.get("members")))]
        if lagg:
            out[lagg] = sorted({m for m in members if m})
    return out


def text_of(value: Any) -> str:
    """A plain field, or a select ({"igb0": {"selected": 1}}) as its selected keys."""
    if isinstance(value, dict):
        return ",".join(k for k, v in value.items() if isinstance(v, dict) and v.get("selected"))
    return "" if value is None else str(value)


def mark_lags(ifaces: list[Interface], config: dict[str, list[str]]) -> None:
    """Each member port names its link aggregation (Interface.lag)."""
    if "lag" not in Interface.model_fields:
        return
    for i in ifaces:
        if i.type != "lag":
            continue
        members = sorted(set(getattr(i, "members", None) or []) | set(config.get(i.name) or []))
        if members and "members" in Interface.model_fields:
            i.members = members
        for m in ifaces:
            if m.name in members:
                m.lag = i.name


def wan_devices(ifaces: list[Interface]) -> set[str]:
    """The WANs and what they ride on (pppoe1 → vlan0.2000 → re0)."""
    by_name = {i.name: i for i in ifaces}
    out: set[str] = set()
    for i in ifaces:
        cur = i if i.wan else None
        while cur is not None and cur.name not in out:
            out.add(cur.name)
            cur = by_name.get(cur.parent or "")
    return out


def bridges_of(ifaces: list[Interface]) -> dict[str, list[str]]:
    return {i.name: list(getattr(i, "members", None) or []) for i in ifaces if i.type == "bridge"}


def router_networks(c: Client, ifaces: list[Interface], missing: list[str]) -> dict[str, Any]:
    """Each VLAN's network and the DHCP's fixed addresses (OPNsense 26.7 and
    later: interface assignments API)."""
    if "networks" not in Device.model_fields:
        return {}
    st = optional("networks", missing, lambda: nets.read_state(c, wan_devices(ifaces)), None)
    if not st:
        return {}
    return newer_fields(
        Device,
        networks=nets.networks(st) or None,
        dhcp_reservations=nets.reservations(c, st) or None,
    )


def paused_devices(c: Client) -> list[dict[str, Any]]:
    """Omini's pauses and, with an Omini that knows them, the blocks set by hand."""
    found = pause.all_paused(c)
    if PausedDevice is None or "rule" not in PausedDevice.model_fields:
        return [{k: v for k, v in p.items() if k != "rule"} for p in found if not p.get("rule")]
    return found


def homelab(c: Client, system_name: str) -> dict[str, Any]:
    """Local DNS names, the local domain and the paused devices. Their
    privileges are only needed by those who use them, so a refusal is quiet."""
    domain = dns.domain_of(system_name, c)
    return newer_fields(
        Device,
        dns_domain=domain,
        dns_records=quiet("the local DNS names", lambda: dns.records(c, domain), []) or None,
        paused=quiet("the paused devices", lambda: paused_devices(c), []) or None,
    )


def extras(
    c: Client,
    ifaces: list[Interface],
    vlan_cfg: dict[str, dict[str, Any]],
    dhcp: list[DhcpLease],
    missing: list[str],
    system_name: str = "",
) -> dict[str, Any]:
    """VLANs, services, VPN peers, DHCP pool usage and the state table."""
    return {
        "vlans": vlans(ifaces, vlan_cfg) or None,
        **router_networks(c, ifaces, missing),
        **homelab(c, system_name),
        "services": optional("services", missing, lambda: services(c), []) or None,
        "vpn_peers": vpn_peers(c) or None,
        "dhcp_pools": dhcp_pools(c, ifaces, dhcp) or None,
        "firewall_states": optional("states", missing, lambda: firewall_states(c), None),
    }


# --- plugin entry points -------------------------------------------------------


def device_key(ifaces: list[Interface], host: str, logical: dict[str, str]) -> str:
    """The LAN's MAC, else the first MAC, else the address Omini uses. The LAN
    is the "lan" interface, whatever description it was given."""
    macs = sorted({i.mac for i in ifaces if i.mac})
    lan = logical.get("lan")
    lan_mac = next((i.mac for i in ifaces if i.mac and lan and i.name == lan), None)
    return lan_mac or (macs[0] if macs else host)


def collect(cfg: Config) -> list[Device]:
    c = client_from(cfg)
    try:
        info = system_information(c)
        missing: list[str] = []
        vlan_cfg = optional("vlans", missing, lambda: vlan_config(c), {}) if EXTRAS else {}
        ifaces, logical, via = optional(
            "interfaces", missing, lambda: interfaces(c, vlan_cfg), ([], {}, {})
        )
        mark_lags(ifaces, quiet("the link aggregations", lambda: lagg_config(c), {}))
        optional("traffic", missing, lambda: traffic(c, ifaces), None)
        versions = info.get("versions") or []
        os_version = versions[0].rsplit("-", 1)[0] if versions else None
        macs = sorted({i.mac for i in ifaces if i.mac})
        ips = sorted({ip.split("/")[0] for i in ifaces for ip in (i.ips or []) if "." in ip})
        host = urlparse(c.base).hostname or c.base
        clock = optional("system", missing, lambda: system_time(c), {})
        dhcp = leases(c, missing)
        name = str(info.get("name") or "")
        device = Device(
            key=device_key(ifaces, host, logical),
            name=name or host,
            host=host,
            role="firewall",
            vendor="OPNsense",
            os_version=os_version,
            uptime_s=uptime_seconds(clock.get("uptime")),
            cpu_pct=optional("system", missing, lambda: cpu_pct(c), None),
            mem_pct=optional("system", missing, lambda: memory_pct(c), None),
            macs=macs or None,
            ips=ips or None,
            interfaces=ifaces or None,
            arp=optional("arp", missing, lambda: arp(c), []) or None,
            **newer_fields(Device, ndp=quiet("the NDP table", lambda: ndp(c), []) or None),
            dhcp_leases=dhcp or None,
            gateways=optional("gateways", missing, lambda: gateways(c, via), []) or None,
            **(health(c, clock, missing) if HEALTH else {}),
            **(extras(c, ifaces, vlan_cfg, dhcp, missing, name) if EXTRAS else {}),
        )
        if missing:
            log.warning("missing privileges: %s", ", ".join(sorted(set(missing))))
        return [device]
    finally:
        c.close()


CHANGES = {
    "network.set": "networks",
    "network.delete": "networks",
    "reservation.set": "networks",
    "reservation.delete": "networks",
    "dns.set": "dns",
    "dns.delete": "dns",
    "wol.send": "wol",
    "pause.set": "pause",
    "pause.delete": "pause",
}


def apply(cfg: Config, change: Any) -> list[Device]:
    """network.set: a VLAN's network (its VLAN on the port toward the switches,
    the interface and gateway, the DHCP range, the access rules); network.delete
    removes it; reservation.*: fixed addresses; dns.*: local names; wol.send:
    a Wake-on-LAN packet; pause.*: a device's internet. OPNsense saves what the
    API changes; the plugin reads the router again until it is as asked."""
    if change.kind not in CHANGES:
        raise PluginError(f"this plugin cannot apply {change.kind}")
    value = change.value if isinstance(change.value, dict) else dict(change.value)
    c = client_from(cfg)
    try:
        if change.kind in ("dns.set", "dns.delete"):
            apply_dns(c, change.kind, value)
        elif change.kind == "wol.send":
            wake(c, value)
        else:
            apply_router(c, change.kind, value)
    except Forbidden as e:
        raise PluginError(
            f"the API user may not use {e}: give it the privilege "
            + privilege_of(str(e), change.kind)
        ) from e
    except NotFound as e:
        raise PluginError(
            f"OPNsense has no {e}: this change needs a newer OPNsense or a plugin it lacks"
        ) from e
    finally:
        c.close()
    return collect(cfg)


# The privilege of each endpoint a change uses, so a refusal names the one
# that is missing (a change reads more than its own endpoints).
ENDPOINT_PRIVILEGES = (
    ("/api/interfaces/vlan_settings/", "Interfaces: VLAN"),
    ("/api/interfaces/assignment/", "Interfaces: Assignments"),
    ("/api/interfaces/overview/", "Status: Interfaces"),
    ("/api/kea/", "Services: DHCP: Kea(v4)"),
    ("/api/dnsmasq/", "Services: Dnsmasq DNS/DHCP: Settings"),
    ("/api/firewall/filter/", "Firewall: Rules"),
    ("/api/firewall/alias/", "Firewall: Alias"),
    ("/api/mdnsrepeater/", "Services: mDNS Repeater"),
    ("/api/unbound/", "Services: Unbound DNS: Edit Host and Domain Override"),
    ("/api/wol/", "Services: Wake on LAN"),
    ("/api/diagnostics/system/", "Lobby: Dashboard"),
)


def privilege_of(path: str, kind: str) -> str:
    """The privilege a refused endpoint needs; the change's own when unknown."""
    return next(
        (p for prefix, p in ENDPOINT_PRIVILEGES if path.startswith(prefix)),
        PRIVILEGES[CHANGES[kind]],
    )


def apply_dns(c: Client, kind: str, value: dict[str, Any]) -> None:
    domain = dns.domain_of(str(system_information(c).get("name") or ""), c)
    if kind == "dns.set":
        fqdn = dns.set_name(c, value, domain)
        nets.wait_for(
            lambda: {"name": fqdn, "ip": str(value["ip"])} in dns.records(c, domain),
            f"the name {fqdn}",
        )
        return
    fqdn = dns.delete_name(c, str(value.get("name") or ""), domain)
    nets.wait_for(
        lambda: not any(r["name"] == fqdn for r in dns.records(c, domain)),
        f"the removal of {fqdn}",
    )


def wol_interface(ifaces: list[Interface], logical: dict[str, str], ip: str) -> str:
    """The interface (lan, opt3) whose network holds ip; the LAN without one."""
    ident = {device: name for name, device in logical.items()}
    if not ip:
        if "lan" in logical:
            return "lan"
        raise PluginError("the firewall has no LAN to wake the device on")
    addr = ipaddress.IPv4Address(ip)
    for i in ifaces:
        for a in i.ips or []:
            if "/" not in a or ":" in a or i.name not in ident:
                continue
            if addr in ipaddress.ip_interface(a).network:
                return ident[i.name]
    raise PluginError(f"no network of the firewall holds {ip}")


def wake(c: Client, value: dict[str, Any]) -> None:
    """Wake-on-LAN through the os-wol plugin."""
    target = nets.norm_mac(value.get("mac"))
    if not target:
        raise PluginError("a MAC address is needed to wake a device")
    ifaces, logical, _ = interfaces(c)
    ifname = wol_interface(ifaces, logical, str(value.get("ip") or ""))
    try:
        c.post("/api/wol/wol/set", {"wake": {"interface": ifname, "mac": target}})
    except NotFound as e:
        raise PluginError(
            "Wake-on-LAN through OPNsense needs the os-wol plugin: "
            "install it in System → Firmware → Plugins"
        ) from e


def lan_ipv6(ifaces: list[Interface], st: nets.State) -> list[str]:
    """The IPv6 addresses (with their prefix) of the LAN-side interfaces: the
    networks a paused device still reaches."""
    lan = {a.ifname: a.device for a in st.assigned}
    devices = {lan[i] for i in pause.lan_interfaces(st) if i in lan}
    return [ip for i in ifaces if i.name in devices for ip in i.ips or [] if ":" in ip]


def apply_router(c: Client, kind: str, value: dict[str, Any]) -> None:
    """Networks, fixed addresses and pauses: they need the interface assignments."""
    ifaces, _, _ = interfaces(c, vlan_config(c))
    wan = wan_devices(ifaces)
    st = nets.read_state(c, wan)
    if st is None:
        raise PluginError(
            "this change needs OPNsense 26.7 or later and the privileges " + PRIVILEGES["networks"]
        )
    if kind == "reservation.set":
        nets.reserve(c, st, value)
        nets.wait_for(
            lambda: any(
                r["mac"] == nets.norm_mac(value["mac"]) and r["ip"] == value["ip"]
                for r in nets.reservations(c, nets.read_state(c, wan) or nets.State())
            ),
            "the reservation",
        )
    elif kind == "reservation.delete":
        nets.unreserve(c, st, value["mac"])
        nets.wait_for(
            lambda: (
                not any(
                    r["mac"] == nets.norm_mac(value["mac"])
                    for r in nets.reservations(c, nets.read_state(c, wan) or nets.State())
                )
            ),
            "the removal of the reservation",
        )
    elif kind == "pause.set":
        ips = pause.set_pause(c, st, value, lan_ipv6(ifaces, st), {i.mac for i in ifaces if i.mac})
        mac = nets.norm_mac(value["mac"])
        nets.wait_for(
            lambda: pause.is_paused(c, nets.read_state(c, wan) or nets.State(), mac, ips),
            "the pause",
        )
    elif kind == "pause.delete":
        mac = nets.norm_mac(value.get("mac"))
        pause.delete_pause(c, st, mac, lan_ipv6(ifaces, st))
        nets.wait_for(
            lambda: not any(p["mac"] == mac for p in pause.all_paused(c)),
            "the end of the pause",
        )
    elif kind == "network.set":
        vid = int(value["vlan"])
        new = vid != 1 and not any(n["vlan"] == vid for n in nets.networks(st))
        before = (
            set(st.vlans),
            {a.ifname for a in st.assigned},
            {nets.text(s.get("subnet")) for s in st.subnets},
        )
        try:
            nets.apply_set(c, st, value, bridges_of(ifaces))
            nets.wait_for(lambda: nets.matches(nets.read_state(c, wan), value), "the network")
        except (PluginError, Forbidden, NotFound):
            if new:
                undo(c, wan, *before)
            raise
    else:
        vid = int(value["vlan"])
        nets.apply_delete(c, st, vid)
        nets.wait_for(
            lambda: (
                not any(
                    n["vlan"] == vid for n in nets.networks(nets.read_state(c, wan) or nets.State())
                )
            ),
            "the removal",
        )


def undo(c: Client, wan: set[str], vlans: set[str], ifnames: set[str], subnets: set[str]) -> None:
    """Removes what a network.set that failed had created (see nets.undo)."""
    try:
        st = nets.read_state(c, wan)
        if st is not None:
            nets.undo(c, st, vlans, ifnames, subnets)
    except Exception:
        log.exception("could not remove what was created for the network")


def backup(cfg: Config) -> list[ConfigBackup]:
    """config.xml, without the revision stamp of the last save."""
    c = client_from(cfg)
    try:
        content = backups.config_xml(c)
        host = urlparse(c.base).hostname or c.base
        ifaces, logical, _ = quiet("the interfaces", lambda: interfaces(c), ([], {}, {}))
        return [
            ConfigBackup(device=device_key(ifaces, host, logical), format="xml", content=content)
        ]
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
        if EXTRAS:
            optional("vlans", missing, lambda: vlan_config(c), None)
            optional("services", missing, lambda: services(c), None)
            optional("states", missing, lambda: firewall_states(c), None)
        versions = info.get("versions") or []
        version = versions[0].rsplit("-", 1)[0] if versions else "OPNsense"
        msg = f"Connected to {info.get('name') or c.base} ({version})"
        if missing:
            msg += ". Missing privileges: " + "; ".join(sorted(set(missing)))
        return msg
    finally:
        c.close()
