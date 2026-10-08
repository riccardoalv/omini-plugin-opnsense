"""A firewall like many homelabs: OPNsense in a VM, PPPoE over a tagged VLAN
on a 2.5G port, a 10G Mellanox card (SFP+ DAC) and a virtio NIC bridged
into the LAN."""

from omini_opnsense.collect import collect

ROWS = [
    {
        "device": "re0",
        "identifier": "opt3",
        "description": "WAN_PHYSICAL",
        "status": "up",
        "is_physical": True,
        "macaddr": "1c:86:0b:00:00:01",
        "media": "2500Base-T <full-duplex,rxpause,txpause>",
        "supported_media": ["autoselect", "2500Base-T\tfull-duplex", "1000baseT\tfull-duplex"],
        "ipv4": [{"ipaddr": "192.168.100.2/24"}],
        "gateways": [],
    },
    {
        "device": "vtnet0",
        "identifier": "opt2",
        "description": "VMS",
        "status": "up",
        "is_physical": True,
        "macaddr": "bc:24:11:00:00:01",
        "media": "10Gbase-T <full-duplex>",
        "supported_media": ["autoselect"],
        "gateways": [],
    },
    {
        "device": "mlxen0",
        "identifier": "opt1",
        "description": "LAN_PHYSICAL",
        "status": "up",
        "is_physical": True,
        "macaddr": "24:8a:07:00:00:01",
        "media": "10Gbase-CX4 <full-duplex,rxpause,txpause>",
        # mlx4 lists every media it knows, copper included: only the current one counts.
        "supported_media": [
            "autoselect",
            "40Gbase-CR4\tfull-duplex",
            "10Gbase-CX4\tfull-duplex",
            "10Gbase-SR\tfull-duplex",
            "1000baseT\tfull-duplex",
        ],
        "gateways": [],
    },
    {
        "device": "bridge0",
        "identifier": "lan",
        "description": "LAN",
        "status": "up",
        "is_physical": False,
        "macaddr": "58:9c:fc:00:00:01",
        "members": {"vtnet0": {"flags": ["learning"]}, "mlxen0": {"flags": ["learning"]}},
        "ipv4": [{"ipaddr": "192.168.1.1/24"}],
        "gateways": [],
    },
    {
        "device": "vlan0.2000",
        "identifier": "",
        "description": "Unassigned Interface",
        "status": "up",
        "is_physical": False,
        "macaddr": "1c:86:0b:00:00:01",
        "vlan": {"tag": "2000", "proto": "802.1q", "parent": "re0"},
        "media": "2500Base-T <full-duplex,rxpause,txpause>",
        "supported_media": ["autoselect"],
    },
    {
        "device": "pppoe1",
        "identifier": "wan",
        "description": "WAN",
        "status": "up",
        "is_physical": False,
        "macaddr": "00:00:00:00:00:00",
        "link_type": "pppoe",
        "ipv4": [{"ipaddr": "100.64.0.20/32"}],
        "ipv6": [{"ipaddr": "2001:db8:1::20/64"}, {"ipaddr": "fe80::1/64"}],
        "gateways": ["100.64.0.1", "fe80::e623:3cff:fefb:1"],
    },
    {
        "device": "tailscale0",
        "identifier": "",
        "description": "Unassigned Interface",
        "status": "up",
        "is_physical": True,
        "macaddr": "00:00:00:00:00:00",
        "supported_media": [],
    },
]

GATEWAYS = {
    "items": [
        {
            "name": "WAN_PPPOE",
            "address": "100.64.0.1",
            "status": "none",
            "loss": "0.0 %",
            "delay": "30.6 ms",
            "stddev": "1.0 ms",
            "monitor": "100.64.0.1",
        },
        {
            "name": "WAN_DHCP6",
            "address": "fe80::e623:3cff:fefb:1",
            "status": "none",
            "loss": "0.0 %",
            "delay": "30.5 ms",
            "stddev": "1.0 ms",
            "monitor": "fe80::e623:3cff:fefb:1",
        },
    ],
    "status": "ok",
}


def test_pppoe_wan_over_a_vlan(opnsense, cfg):
    opnsense.routes["/api/interfaces/overview/interfaces_info/1"] = {"rows": ROWS}
    opnsense.routes["/api/routes/gateway/status"] = GATEWAYS
    [fw] = collect(cfg)
    ports = {i.name: i for i in fw.interfaces}

    wan = ports["pppoe1"]
    assert (wan.wan, wan.type, wan.parent, wan.speed_mbps) == (True, "tunnel", "vlan0.2000", 2500)
    assert wan.ips == ["100.64.0.20/32", "2001:db8:1::20/64"]
    assert not ports["re0"].wan and not ports["bridge0"].wan
    assert ports["vlan0.2000"].parent == "re0"
    assert {g.name: g.interface for g in fw.gateways} == {
        "WAN_PPPOE": "pppoe1",
        "WAN_DHCP6": "pppoe1",
    }


def test_connectors_and_virtual_nics(opnsense, cfg):
    opnsense.routes["/api/interfaces/overview/interfaces_info/1"] = {"rows": ROWS}
    [fw] = collect(cfg)
    ports = {i.name: i for i in fw.interfaces}
    assert (ports["re0"].connector, ports["re0"].speed_mbps) == ("rj45", 2500)
    assert (ports["mlxen0"].connector, ports["mlxen0"].speed_mbps) == ("sfp", 10000)
    # virtio: a VM's NIC, no jack and no real speed
    assert (ports["vtnet0"].type, ports["vtnet0"].connector, ports["vtnet0"].speed_mbps) == (
        "other",
        None,
        None,
    )
    assert ports["tailscale0"].type == "tunnel" and ports["bridge0"].type == "bridge"
    # The LAN bridge runs at its physical member's speed (the 10G SFP+), not the VM NIC's.
    assert ports["bridge0"].speed_mbps == 10000 and ports["bridge0"].connector is None
    assert (
        ports["bridge0"].members == sorted(ports["bridge0"].members)
        and "mlxen0" in ports["bridge0"].members
    )


def test_connector_of_a_port_that_is_down(opnsense, cfg):
    rows = [
        {
            "device": "ix0",
            "status": "no carrier",
            "media": "autoselect",
            "supported_media": ["autoselect", "10Gbase-SR\tfull-duplex", "10Gbase-LR"],
        },
        {
            "device": "ix1",
            "status": "no carrier",
            "media": "autoselect",
            "supported_media": ["autoselect", "10Gbase-T\tfull-duplex", "1000baseT"],
        },
        {"device": "igb2", "status": "no carrier", "media": "autoselect", "supported_media": []},
    ]
    opnsense.routes["/api/interfaces/overview/interfaces_info/1"] = {"rows": rows}
    [fw] = collect(cfg)
    assert [(i.name, i.connector) for i in fw.interfaces] == [
        ("ix0", "sfp"),
        ("ix1", "rj45"),
        ("igb2", None),
    ]


def test_pppoe_carrier_is_the_unassigned_port():
    """PPPoE straight on a port (no VLAN): the port up with no role of its own,
    not the other WAN's port, nor a link aggregation's member."""
    from omini_opnsense.collect import carrier

    rows = [
        {
            "device": "igc0",
            "status": "up",
            "description": "Unassigned Interface",
            "is_physical": True,
        },
        {
            "device": "igc1",
            "identifier": "opt1",
            "description": "WAN_LTE",
            "status": "up",
            "is_physical": True,
        },
        {"device": "ax0", "status": "up", "is_physical": True},
        {
            "device": "lagg0",
            "identifier": "lan",
            "status": "up",
            "laggport": {"ax0": {}, "ax1": {}},
        },
        {"device": "ax1", "status": "up", "is_physical": True},
        {"device": "pppoe0", "identifier": "wan", "description": "WAN_FIBER", "status": "up"},
    ]
    assert carrier(rows) == "igc0"


def test_lagg_members():
    from omini_opnsense.collect import members_of

    assert members_of({"laggport": {"ax1": {}, "ax0": {}}}, "lag") == {"members": ["ax0", "ax1"]}
    assert members_of({"laggport": {"ax0": {}}}, "ethernet") == {}


def test_a_gateway_that_is_down_has_no_delay(opnsense, cfg):
    from omini_opnsense.collect import gateways

    class Fake:
        def get(self, *paths):
            return {
                "items": [
                    {
                        "name": "FIBER",
                        "address": "203.0.113.1",
                        "status": "down",
                        "delay": "~",
                        "loss": "~",
                    },
                    {
                        "name": "PENDING",
                        "address": "~",
                        "status": "none",
                        "delay": "~",
                        "loss": "~",
                    },
                    {
                        "name": "LTE",
                        "address": "192.168.8.1",
                        "status": "none",
                        "delay": "21.3 ms",
                        "loss": "0.0 %",
                    },
                ]
            }

    got = {g.name: g.status for g in gateways(Fake())}
    assert got == {"FIBER": "down", "PENDING": "unknown", "LTE": "up"}


def test_a_dial_up_gateway_that_is_down_keeps_its_interface():
    """PPPoE down: no address, no gateway list on the interface; the gateway
    is still tied to it by its name (WAN_FIBER_PPPOE → the WAN_FIBER port)."""
    from omini_opnsense.collect import gateway_interface

    via = {"descr:WAN_FIBER": "pppoe0", "descr:WAN_LTE": "igc1", "192.168.8.1": "igc1"}
    down = {"name": "WAN_FIBER_PPPOE", "address": "~", "monitor": "~", "status": "down"}
    assert gateway_interface(down, via) == "pppoe0"
    assert gateway_interface({"name": "LTE", "address": "192.168.8.1"}, via) == "igc1"
    assert gateway_interface({"name": "OTHER_GW_2", "address": "~"}, via) is None
