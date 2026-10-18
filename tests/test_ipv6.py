"""IPv6: the firewall's own addresses, DHCPv6 leases, IPv6 gateways and AAAA
records (read only: dns.set and dns.delete write A records and keep them)."""

import json
from pathlib import Path

from test_homelab import apply, fw, names  # noqa: F401  (the fw fixture)

from omini_opnsense.collect import collect

V6 = Path(__file__).parent / "fixtures" / "ipv6"


def load(opnsense, *paths):
    for path in paths:
        f = V6 / (path.removeprefix("/api/").replace("/", "__") + ".json")
        opnsense.routes[path] = json.loads(f.read_text())


def test_dhcpv6_leases_of_kea_and_isc(opnsense, cfg):
    load(opnsense, "/api/kea/leases6/search", "/api/dhcpv6/leases/search_lease")
    [dev] = collect(cfg)
    v6 = [(lease.ip, lease.mac, lease.hostname) for lease in dev.dhcp_leases if ":" in lease.ip]
    # A lease without a MAC, an expired one and a delegated prefix are left out.
    assert v6 == [
        ("2001:db8:1::1000", "aa:bb:cc:dd:ee:07", "laptop"),
        ("2001:db8:1::2000", "aa:bb:cc:dd:ee:0a", None),
        ("fd00::50", "aa:bb:cc:dd:ee:06", "v6"),
    ]
    assert dev.dhcp_pools  # IPv6 leases do not count in the IPv4 pools


def test_dhcpv6_is_optional(opnsense, cfg):
    load(opnsense, "/api/kea/leases6/search")
    opnsense.forbidden.add("/api/kea/leases6/")
    opnsense.broken.add("/api/dhcpv6/leases/search_lease")
    [dev] = collect(cfg)
    assert {lease.ip for lease in dev.dhcp_leases} >= {"192.168.1.100"}


def test_ipv6_gateways(opnsense, cfg):
    opnsense.routes["/api/routes/gateway/status"]["items"].append(
        {
            "name": "WAN_DHCP6",
            "address": "fe80::1%igb0",
            "status": "none",
            "loss": "0.0 %",
            "delay": "3.4 ms",
            "stddev": "0.2 ms",
            "monitor": "2001:db8::1",
        }
    )
    [dev] = collect(cfg)
    gw = next(g for g in dev.gateways if g.name == "WAN_DHCP6")
    assert (gw.address, gw.interface, gw.status, gw.rtt_ms) == ("fe80::1%igb0", "igb0", "up", 3.4)


def test_aaaa_records_are_read_and_kept(fw, cfg):  # noqa: F811
    fw.overrides["h3"] = {
        "enabled": "1",
        "hostname": "printer",
        "domain": "localdomain",
        "rr": "AAAA (IPv6 address)",
        "server": "fd00::30",
        "description": "set by hand",
    }
    fw.overrides["h4"] = {
        "enabled": "1",
        "hostname": "nas",
        "domain": "localdomain",
        "rr": "AAAA",
        "server": "2001:db8:1::20",
        "description": "",
    }
    [dev] = collect(cfg)
    assert names([dev]) == {
        ("printer.localdomain", "192.168.1.30"),
        ("printer.localdomain", "fd00::30"),
        ("nas.localdomain", "2001:db8:1::20"),
    }
    # dns.set adds an A record next to the AAAA one; dns.delete removes only it.
    devices = apply(cfg, "dns.set", {"name": "nas.localdomain", "ip": "192.168.1.20"})
    assert ("nas.localdomain", "192.168.1.20") in names(devices)
    assert fw.overrides["h4"]["server"] == "2001:db8:1::20"
    devices = apply(cfg, "dns.delete", {"name": "printer.localdomain"})
    assert names(devices) == {
        ("printer.localdomain", "fd00::30"),
        ("nas.localdomain", "192.168.1.20"),
        ("nas.localdomain", "2001:db8:1::20"),
    }
    assert "h3" in fw.overrides and "h1" not in fw.overrides
    # A name with only an AAAA record has no A record to remove.
    apply(cfg, "dns.delete", {"name": "nas.localdomain"})
    assert "h4" in fw.overrides


def test_a_dnsmasq_host_keeps_its_ipv6_addresses(fw, cfg):  # noqa: F811
    fw.unbound_on = False
    fw.dnsmasq.update(enable="1", port="")
    fw.hosts["d1"] = {"host": "nas", "domain": "lan", "ip": "192.168.1.20,fd00::20", "hwaddr": ""}
    fw.hosts["d2"] = {"host": "cam", "domain": "lan", "ip": "fd00::21", "hwaddr": ""}
    [dev] = collect(cfg)
    assert names([dev]) == {
        ("nas.lan", "192.168.1.20"),
        ("nas.lan", "fd00::20"),
        ("cam.lan", "fd00::21"),
    }
    apply(cfg, "dns.set", {"name": "nas.lan", "ip": "192.168.1.21"})
    assert fw.hosts["d1"]["ip"] == "192.168.1.21,fd00::20"
    devices = apply(cfg, "dns.delete", {"name": "nas.lan"})
    assert fw.hosts["d1"]["ip"] == "fd00::20"
    assert names(devices) == {("nas.lan", "fd00::20"), ("cam.lan", "fd00::21")}
    # A name with only IPv6 addresses is not Omini's to remove.
    apply(cfg, "dns.delete", {"name": "cam.lan"})
    assert "d2" in fw.hosts
