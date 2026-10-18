"""Port forwards: Firewall → NAT → Destination NAT (OPNsense 25.7 and later)."""

from omini_opnsense.collect import collect
from omini_opnsense.forwards import port_range


def test_port_forwards(opnsense, cfg):
    [fw] = collect(cfg)
    got = [
        (
            f.protocol,
            f.external_port,
            f.external_port_end,
            f.internal_ip,
            f.internal_port,
            f.source,
            f.interface,
            f.description,
            f.enabled,
            f.upnp,
        )
        for f in fw.port_forwards
    ]
    assert got == [
        ("tcp", 443, None, "192.168.1.20", 8443, None, "igb0", "NAS web", True, False),
        (
            "udp",
            27015,
            27030,
            "192.168.1.40",
            27015,
            "198.51.100.0/24",
            "igb0",
            "Game server",
            False,
            False,
        ),
        # A well-known port name; the first of several interfaces.
        ("tcp/udp", 80, None, "192.168.1.21", 80, None, "igb0", None, True, False),
        # A port alias is left out (its ports are not in the rule), and so is
        # a "no redirect" rule; IPv6 forwards are reported like IPv4 ones.
        ("tcp", 22, None, "2001:db8:1::50", 22, None, "igb0", "SSH over IPv6", True, False),
    ]


def test_no_destination_nat_api(opnsense, cfg):
    # Before 25.7 the port forwards have no API: none are reported.
    opnsense.routes.pop("/api/firewall/d_nat/search_rule")
    [fw] = collect(cfg)
    assert fw.port_forwards is None


def test_port_forwards_without_the_privilege(opnsense, cfg):
    opnsense.forbidden.add("/api/firewall/d_nat/")
    [fw] = collect(cfg)
    assert fw.port_forwards is None and fw.interfaces


def test_port_range():
    assert port_range("8000:8010") == (8000, 8010)
    assert port_range("53-53") == (53, None)
    assert port_range("https") == (443, None)
    assert port_range("") is None
    assert port_range("90-80") is None
    assert port_range("70000") is None
