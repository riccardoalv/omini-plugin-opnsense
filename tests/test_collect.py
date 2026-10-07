import pytest
from omini_sdk import PluginError

from omini_opnsense.collect import collect, speed_from_media, uptime_seconds
from omini_opnsense.collect import test as connection_test


def test_reads_the_firewall(opnsense, cfg):
    [fw] = collect(cfg)
    assert fw.name == "opnsense.localdomain"
    assert fw.key == "00:0d:b9:aa:bb:cc"  # LAN MAC
    assert fw.role == "firewall" and fw.os_version == "OPNsense 25.7.4"
    assert fw.host == "192.168.1.1"
    assert fw.uptime_s == ((3 * 24 + 4) * 60 + 12) * 60 + 9
    assert fw.mem_pct == 25.0
    assert fw.cpu_pct == 3  # the second sample, not the average since boot
    assert fw.ips == ["10.0.20.1", "192.168.1.1", "203.0.113.10"]


def test_ports_with_speed_and_traffic(opnsense, cfg):
    [fw] = collect(cfg)
    ports = {i.name: i for i in fw.interfaces}
    assert list(ports) == ["igb0", "igb1", "igb2", "vtnet0_vlan20"]  # no lo0 / enc0
    wan, lan, spare, iot = ports.values()
    assert (wan.description, wan.up, wan.speed_mbps, wan.duplex) == ("WAN", True, 2500, "full")
    assert wan.media == "2500Base-T <full-duplex>" and wan.rx_bytes == 98765432100
    assert lan.speed_mbps == 1000 and lan.rx_errors == 2
    assert lan.ips == ["192.168.1.1/24", "fd00::1/64"]  # link-local left out
    assert (spare.description, spare.up, spare.speed_mbps) == (None, False, None)
    assert iot.type == "vlan" and iot.rx_bytes == 5555 and iot.tx_errors == 1  # from traffic


def test_arp_and_leases_from_every_dhcp_server(opnsense, cfg):
    [fw] = collect(cfg)
    assert [(a.ip, a.mac, a.interface) for a in fw.arp] == [
        ("192.168.1.50", "aa:bb:cc:dd:ee:01", "igb1")
    ]
    assert [(lease.ip, lease.hostname) for lease in fw.dhcp_leases] == [
        ("192.168.1.100", "phone"),  # ISC
        ("192.168.1.102", "tv"),  # dnsmasq, never expires
        ("192.168.1.103", None),  # dnsmasq, unknown name
    ]
    assert fw.dhcp_leases[2].expires_at.isoformat() == "2100-01-01T00:00:00+00:00"


def test_gateways(opnsense, cfg):
    [fw] = collect(cfg)
    gw = {g.name: g for g in fw.gateways}
    assert (gw["WAN_DHCP"].status, gw["WAN_DHCP"].rtt_ms, gw["WAN_DHCP"].loss_pct) == ("up", 1.2, 0)
    assert gw["WAN2_PPPOE"].status == "down" and gw["WAN2_PPPOE"].address is None
    assert gw["VPN_GW"].status == "unknown" and gw["VPN_GW"].rtt_ms is None


def test_missing_privileges_skip_data_and_are_reported(opnsense, cfg):
    opnsense.forbidden = {"/api/routes/", "/api/diagnostics/interface/"}
    [fw] = collect(cfg)
    assert fw.gateways is None and fw.arp is None
    assert fw.interfaces  # the rest still works
    msg = connection_test(cfg)
    assert msg.startswith(
        "Connected to opnsense.localdomain (OPNsense 25.7.4). Missing privileges:"
    )
    assert "System: Gateways" in msg and "Diagnostics: ARP Table" in msg


def test_older_versions_use_camel_case_urls(opnsense, cfg):
    # 25.1 and older: the dashboard privilege matches systemInformation, not system_information.
    for snake, camel in [
        ("system_information", "systemInformation"),
        ("system_resources", "systemResources"),
        ("system_time", "systemTime"),
    ]:
        old = f"/api/diagnostics/system/{snake}"
        opnsense.routes[f"/api/diagnostics/system/{camel}"] = opnsense.routes.pop(old)
        opnsense.forbidden.add(old)
    [fw] = collect(cfg)
    assert fw.name == "opnsense.localdomain" and fw.mem_pct == 25.0


def test_errors_the_user_can_act_on(opnsense, cfg):
    opnsense.auth = ("other", "secret")
    with pytest.raises(PluginError, match="rejected the API key"):
        connection_test(cfg)
    opnsense.auth = ("key", "secret")
    opnsense.forbidden = {"/api/diagnostics/system/"}
    with pytest.raises(PluginError, match="Lobby: Dashboard"):
        collect(cfg)
    cfg["url"] = ""
    with pytest.raises(PluginError, match="required"):
        collect(cfg)


def test_unreachable_host(cfg):
    cfg["url"] = "https://127.0.0.1:9"
    with pytest.raises(PluginError, match="cannot connect"):
        connection_test(cfg)


@pytest.mark.parametrize(
    ("media", "speed"),
    [
        ("1000baseT <full-duplex>", 1000),
        ("2500Base-T <full-duplex>", 2500),
        ("10Gbase-T <full-duplex>", 10000),
        ("100baseTX <half-duplex>", 100),
        ("autoselect", None),
        ("", None),
    ],
)
def test_speed_from_media(media, speed):
    assert speed_from_media(media) == speed


def test_uptime_in_any_language():
    assert uptime_seconds("04:12:09") == 15129
    assert uptime_seconds("1 dia, 00:00:01") == 86401
    assert uptime_seconds("unknown") is None
