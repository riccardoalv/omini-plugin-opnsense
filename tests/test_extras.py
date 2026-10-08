"""VLANs, SFP modules, services, VPN peers, DHCP pool usage and firewall states."""

from datetime import datetime, timezone

import pytest

from omini_opnsense.collect import collect, dbm, ip_range, transceiver
from omini_opnsense.collect import test as connection_test


def test_vlans_from_the_configuration(opnsense, cfg):
    [fw] = collect(cfg)
    assert [(v.id, v.name, v.interface, v.subnet) for v in fw.vlans] == [
        (20, "IoT devices", "vtnet0_vlan20", "10.0.20.0/24"),
        (30, "Guests", "vlan01", None),  # configured, not assigned: no address
    ]
    iot = next(i for i in fw.interfaces if i.name == "vtnet0_vlan20")
    assert (iot.type, iot.vlan, iot.parent) == ("vlan", 20, "vtnet0")


def test_vlans_without_the_vlan_privilege(opnsense, cfg):
    # The VLAN interfaces seen still give their ids (here from the device name).
    opnsense.forbidden = {"/api/interfaces/vlan_settings/"}
    [fw] = collect(cfg)
    assert [(v.id, v.name, v.interface) for v in fw.vlans] == [(20, "IOT", "vtnet0_vlan20")]
    assert "Interfaces: VLAN" in connection_test(cfg)


def test_vlan_id_from_ifconfig(opnsense, cfg):
    opnsense.routes.pop("/api/interfaces/vlan_settings/search_item")
    opnsense.routes["/api/interfaces/overview/interfaces_info/1"] = {
        "rows": [
            {
                "device": "vlan02",
                "identifier": "opt4",
                "description": "CAMERAS",
                "status": "up",
                "vlan": {"tag": "40", "proto": "802.1q", "parent": "igb1"},
                "ipv4": [{"ipaddr": "10.0.40.1/24"}],
            }
        ]
    }
    [fw] = collect(cfg)
    [cams] = fw.interfaces
    assert (cams.vlan, cams.parent) == (40, "igb1")
    assert [(v.id, v.name, v.subnet) for v in fw.vlans] == [(40, "CAMERAS", "10.0.40.0/24")]


def test_sfp_module_of_a_port(opnsense, cfg):
    # As legacy_interfaces_details() parses `ifconfig -v` (a QSFP+ module: one
    # line per lane; plain SFP modules only show temperature and voltage there).
    opnsense.routes["/api/interfaces/overview/interfaces_info/1"] = {
        "rows": [
            {
                "device": "ix0",
                "identifier": "lan",
                "description": "LAN",
                "status": "up",
                "macaddr": "00:1b:21:00:00:01",
                "media": "",
                "sfp": {
                    "plugged": "QSFP+ 40G Base-SR4 (MPO 1x12 Parallel Optic)",
                    "vendor": "FS",
                    "part_number": " QSFP-SR4-40G",
                    "serial_number": "G2010012345",
                    "manufacturing_date": "2020-01-01",
                    "temperature": "35.12 C",
                    "voltage": "3.29 ",
                    "lane_1_rx_power": "0.55 mW (-2.60 dBm)",
                    "lane_1_tx_bias": "6.50 mA",
                    "lane_2_rx_power": "0.40 mW (-3.98 dBm)",
                    "lane_2_tx_bias": "6.70 mA",
                },
            },
            {"device": "igb0", "identifier": "wan", "status": "up", "media": "1000baseT"},
        ]
    }
    [fw] = collect(cfg)
    ix0, igb0 = fw.interfaces
    t = ix0.transceiver
    assert (t.vendor, t.part, t.serial, t.type) == (
        "FS",
        "QSFP-SR4-40G",
        "G2010012345",
        "40G Base-SR4",
    )
    assert (t.temperature_c, t.voltage_v) == (35.12, 3.29)
    assert (t.rx_power_dbm, t.bias_ma) == (-3.98, 6.70)  # the weakest lane
    assert t.tx_power_dbm is None and t.wavelength_nm is None  # not read by OPNsense
    assert ix0.connector == "qsfp"  # from the module, the media being unknown
    assert igb0.transceiver is None


def test_transceiver_parsers():
    assert transceiver(None) is None and transceiver({"plugged": ""}) is None
    t = transceiver({"plugged": "SFP/SFP+/SFP28 10G Base-SR (LC)", "temperature": "30.00 C"})
    assert (t.type, t.temperature_c, t.rx_power_dbm) == ("10G Base-SR", 30.0, None)
    assert dbm("0.55 mW (-2.59 dBm)") == -2.59
    assert dbm("1.00 mW") == 0.0 and dbm("0.00 mW") is None and dbm(None) is None


def test_services(opnsense, cfg):
    [fw] = collect(cfg)
    assert [(s.name, s.description, s.running, s.enabled) for s in fw.services] == [
        ("configd", "System Configuration Daemon", True, True),
        ("openvpn/1", "OpenVPN server: Road warriors", False, True),
        ("unbound", "Unbound DNS", True, True),
    ]


def test_vpn_peers(opnsense, cfg):
    [fw] = collect(cfg)
    peers = {p.name: p for p in fw.vpn_peers}
    phone = peers["Phone"]
    assert (phone.protocol, phone.endpoint, phone.address, phone.connected) == (
        "wireguard",
        "198.51.100.7:43210",
        "10.10.0.2/32",
        True,
    )
    assert phone.last_handshake == datetime.fromtimestamp(1791370000, tz=timezone.utc)
    assert (phone.rx_bytes, phone.tx_bytes) == (123456, 654321)
    # A peer without a name in OPNsense: its tunnel and the start of its key.
    laptop = peers["Home bGFwdG9w"]
    assert (laptop.endpoint, laptop.connected, laptop.last_handshake) == (None, False, None)

    alice = peers["alice"]  # connected to an OpenVPN server
    assert (alice.protocol, alice.endpoint, alice.address, alice.connected) == (
        "openvpn",
        "198.51.100.20:1194",
        "10.8.0.6",
        True,
    )
    assert (alice.rx_bytes, alice.tx_bytes) == (1048576, 2097152)
    office = peers["Office"]  # the firewall's own OpenVPN client
    assert (office.connected, office.endpoint, office.rx_bytes) == (True, "203.0.113.50:1194", 5000)
    assert "Site to site" not in peers  # a server with nobody connected is no peer

    branch = peers["Branch office"]
    assert (branch.protocol, branch.endpoint, branch.connected, branch.rx_bytes) == (
        "ipsec",
        "203.0.113.99",
        True,
        7777,
    )
    con2 = peers["con2"]
    assert (con2.endpoint, con2.connected, con2.rx_bytes) == (None, False, None)


def test_vpn_not_used_or_forbidden(opnsense, cfg):
    # No privilege for WireGuard, OpenVPN missing: only IPsec is read, and a VPN
    # nobody uses is not reported as a missing privilege.
    opnsense.forbidden = {"/api/wireguard/"}
    opnsense.routes.pop("/api/openvpn/service/search_sessions")
    [fw] = collect(cfg)
    assert {p.protocol for p in fw.vpn_peers} == {"ipsec"}
    assert "WireGuard" not in connection_test(cfg)

    opnsense.routes.pop("/api/ipsec/sessions/search_phase1")
    [fw] = collect(cfg)
    assert fw.vpn_peers is None


def test_firewall_states(opnsense, cfg):
    [fw] = collect(cfg)
    assert (fw.firewall_states.current, fw.firewall_states.limit) == (1234, 1000000)


def test_firewall_states_forbidden(opnsense, cfg):
    opnsense.forbidden = {"/api/diagnostics/firewall/"}
    [fw] = collect(cfg)
    assert fw.firewall_states is None
    assert fw.services  # the rest still works
    assert "Diagnostics: Firewall statistics" in connection_test(cfg)


def test_dhcp_pool_usage_with_dnsmasq(opnsense, cfg):
    [fw] = collect(cfg)
    # 192.168.1.100-199 holds the ISC and dnsmasq leases of the fixtures;
    # the IPv6 range (no end address) is left out.
    assert [(p.network, p.total, p.used) for p in fw.dhcp_pools] == [("192.168.1.0/24", 100, 3)]


def test_dhcp_pool_usage_with_kea(opnsense, cfg):
    opnsense.routes.pop("/api/dnsmasq/settings/search_range")
    opnsense.routes["/api/kea/dhcpv4/search_subnet"] = {
        "rows": [
            {
                "uuid": "0d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6",
                "subnet": "192.168.1.0/24",
                "pools": "192.168.1.100 - 192.168.1.101\n192.168.1.128/30",
                "description": "LAN",
            },
            {"uuid": "1e2f3a4b-5c6d-4e7f-8a91-92a3b4c5d6e7", "subnet": "10.0.20.0/24", "pools": ""},
        ],
        "rowCount": 2,
        "total": 2,
        "current": 1,
    }
    [fw] = collect(cfg)
    assert [(p.network, p.total, p.used) for p in fw.dhcp_pools] == [("192.168.1.0/24", 6, 1)]


def test_dhcp_ranges_forbidden(opnsense, cfg):
    opnsense.forbidden = {"/api/dnsmasq/settings/"}
    [fw] = collect(cfg)
    assert fw.dhcp_pools is None
    assert fw.dhcp_leases  # leases still read


@pytest.mark.parametrize(
    ("text", "size"),
    [
        ("192.168.1.10-192.168.1.19", 10),
        ("192.168.1.0/28", 16),
        ("192.168.1.20-192.168.1.10", None),
        ("fd00::1-fd00::9", None),
        ("", None),
    ],
)
def test_ip_range(text, size):
    r = ip_range(text)
    assert (int(r[1]) - int(r[0]) + 1 if r else None) == size
