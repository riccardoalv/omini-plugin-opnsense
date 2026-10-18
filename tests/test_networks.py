import itertools
import json

import httpx
import pytest
from omini_sdk import Change, PluginError

import omini_opnsense.collect as collect_module


class Router:
    """The parts of OPNsense 26.7 that hold a network, with their state:
    assignments, VLANs, Kea and the firewall's rules and aliases."""

    def __init__(self):
        ids = itertools.count(1)
        self.uuid = lambda: f"uuid-{next(ids)}"
        self.assigned = {
            "wan": {"if": "igb0", "descr": "WAN", "type4": "dhcp", "ipaddr": "", "enable": "1"},
            "lan": {
                "if": "igb1",
                "descr": "LAN",
                "type4": "staticv4",
                "ipaddr": "192.168.1.1/24",
                "enable": "1",
            },
            "opt1": {
                "if": "vtnet0_vlan20",
                "descr": "IOT",
                "type4": "staticv4",
                "ipaddr": "10.0.20.1/24",
                "enable": "1",
            },
        }
        self.vlans = {
            "v20": {"if": "vtnet0", "tag": "20", "descr": "IoT devices", "vlanif": "vtnet0_vlan20"},
        }
        self.kea = {"enabled": "1", "interfaces": "lan"}
        self.subnets = {
            "s1": {"subnet": "192.168.1.0/24", "pools": "192.168.1.100-192.168.1.199"},
        }
        self.rules = {
            "r1": {
                "enabled": "1",
                "action": "pass",
                "interface": "lan",
                "source_net": "lan",
                "destination_net": "any",
            },
        }
        self.aliases = {}
        self.reservations = {}
        self.mdns = {"enabled": "0", "interfaces": "lan"}  # None: the plugin is not installed
        self.posts = []
        self.assignments_api = True

    def search(self, items, key="uuid"):
        return {"rows": [{key: k, **v} for k, v in items.items()], "rowCount": len(items)}

    def handle(self, method, path, body):
        if path.startswith("/api/interfaces/assignment/") and not self.assignments_api:
            return 404, {"errorMessage": "Endpoint not found"}
        if method == "GET":
            return self.get(path)
        self.posts.append(path)
        return self.post(path, body or {})

    def get(self, path):
        if path == "/api/interfaces/assignment/search_item":
            return 200, self.search(self.assigned, "identifier")
        if path == "/api/interfaces/vlan_settings/search_item":
            return 200, self.search(self.vlans)
        if path == "/api/kea/dhcpv4/get":
            return 200, {"dhcpv4": {"general": dict(self.kea)}}
        if path == "/api/kea/dhcpv4/search_subnet":
            return 200, self.search(self.subnets)
        if path == "/api/firewall/filter/search_rule":
            return 200, self.search(self.rules)
        if path == "/api/firewall/alias/search_item":
            return 200, self.search(self.aliases)
        if path == "/api/mdnsrepeater/settings/get":
            if self.mdns is None:
                return 404, {"errorMessage": "Endpoint not found"}
            return 200, {"mdnsrepeater": dict(self.mdns)}
        if path == "/api/kea/dhcpv4/search_reservation":
            return 200, self.search(self.reservations)
        return None

    def post(self, path, body):
        parts = path.split("/")
        last = parts[-1]
        if path == "/api/interfaces/vlan_settings/add_item":
            v = body["vlan"]
            self.vlans[self.uuid()] = {**v, "vlanif": f"vlan0.{v['tag']}"}
        elif path.startswith("/api/interfaces/vlan_settings/del_item/"):
            del self.vlans[last]
        elif path == "/api/interfaces/assignment/add_item":
            n = 1 + max(int(k[3:]) for k in self.assigned if k.startswith("opt"))
            self.assigned[f"opt{n}"] = body["interface"]
        elif path.startswith("/api/interfaces/assignment/set_item/"):
            self.assigned[last].update(body["interface"])
        elif path.startswith("/api/interfaces/assignment/del_item/"):
            del self.assigned[last]
        elif path == "/api/kea/dhcpv4/add_subnet":
            self.subnets[self.uuid()] = body["subnet4"]
        elif path.startswith("/api/kea/dhcpv4/set_subnet/"):
            self.subnets[last].update(body["subnet4"])
        elif path.startswith("/api/kea/dhcpv4/del_subnet/"):
            del self.subnets[last]
        elif path == "/api/kea/dhcpv4/set":
            self.kea.update(body["dhcpv4"]["general"])
        elif path == "/api/firewall/filter/add_rule":
            self.rules[self.uuid()] = body["rule"]
        elif path.startswith("/api/firewall/filter/del_rule/"):
            del self.rules[last]
        elif path == "/api/kea/dhcpv4/add_reservation":
            self.reservations[self.uuid()] = body["reservation"]
        elif path.startswith("/api/kea/dhcpv4/set_reservation/"):
            self.reservations[last].update(body["reservation"])
        elif path.startswith("/api/kea/dhcpv4/del_reservation/"):
            del self.reservations[last]
        elif path == "/api/mdnsrepeater/settings/set":
            self.mdns.update(body["mdnsrepeater"])
        elif path == "/api/firewall/alias/add_item":
            self.aliases[self.uuid()] = body["alias"]
        elif not last.endswith(("reconfigure", "apply")):
            return 404, {"errorMessage": "Endpoint not found"}
        return 200, {"result": "saved", "status": "ok"}

    def on(self, ifname):
        return [r for r in self.rules.values() if r["interface"] == ifname]


@pytest.fixture
def router(opnsense):
    r = Router()
    fallback = opnsense.handler

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        out = r.handle(request.method, request.url.path, body)
        if out is None:
            return fallback(request)
        return httpx.Response(out[0], json=out[1])

    opnsense.handler = handler
    collect_module.Client.keywords["transport"] = httpx.MockTransport(handler)
    return r


def networks(devices):
    return {n.vlan: n for n in devices[0].networks or []}


def iot40(**extra):
    return {
        "vlan": 40,
        "name": "CAMERAS",
        "parent": "igb1",
        "gateway": "10.0.40.1/24",
        "dhcp": {"enabled": True, "from": "10.0.40.100", "to": "10.0.40.200"},
        "access": "internet",
        **extra,
    }


def test_reads_the_networks(router, cfg):
    nets = networks(collect_module.collect(cfg))
    lan, iot = nets[1], nets[20]
    assert (lan.interface, lan.gateway, lan.access) == ("lan", "192.168.1.1/24", "all")
    assert (lan.dhcp.enabled, lan.dhcp.from_, lan.dhcp.to) == (
        True,
        "192.168.1.100",
        "192.168.1.199",
    )
    assert (iot.interface, iot.device, iot.parent, iot.name) == (
        "opt1",
        "vtnet0_vlan20",
        "vtnet0",
        "IOT",
    )
    # No DHCP on it, and no rule Omini knows: custom, left as it is.
    assert not iot.dhcp.enabled
    assert iot.access == "custom"


def test_creates_a_network(router, cfg):
    devices = collect_module.apply(cfg, Change(device="x", kind="network.set", value=iot40()))
    vlan = next(v for v in router.vlans.values() if v["tag"] == "40")
    assert vlan["if"] == "igb1"
    assigned = router.assigned["opt2"]
    assert (assigned["if"], assigned["ipaddr"], assigned["type4"]) == (
        "vlan0.40",
        "10.0.40.1/24",
        "staticv4",
    )
    assert "opt2" in router.kea["interfaces"].split(",")
    subnet = next(s for s in router.subnets.values() if s["subnet"] == "10.0.40.0/24")
    assert subnet["pools"] == "10.0.40.100-10.0.40.200"
    shapes = [(r["action"], r["destination_net"]) for r in router.on("opt2")]
    assert shapes == [("pass", "opt2ip"), ("block", "omini_private"), ("pass", "any")]
    assert any(a["name"] == "omini_private" for a in router.aliases.values())
    got = networks(devices)[40]
    assert (got.gateway, got.access, got.dhcp.from_) == ("10.0.40.1/24", "internet", "10.0.40.100")


def test_changes_a_network_and_its_access(router, cfg):
    collect_module.apply(cfg, Change(device="x", kind="network.set", value=iot40()))
    router.posts.clear()
    collect_module.apply(
        cfg,
        Change(
            device="x",
            kind="network.set",
            value=iot40(
                access="all", dhcp={"enabled": True, "from": "10.0.40.50", "to": "10.0.40.99"}
            ),
        ),
    )
    assert [r["destination_net"] for r in router.on("opt2")] == ["any"]
    assert next(s for s in router.subnets.values() if s["subnet"] == "10.0.40.0/24")["pools"] == (
        "10.0.40.50-10.0.40.99"
    )
    # The VLAN and the interface were already there: not created again.
    assert "/api/interfaces/vlan_settings/add_item" not in router.posts
    assert "/api/interfaces/assignment/add_item" not in router.posts


def test_custom_access_keeps_the_rules(router, cfg):
    router.rules["r9"] = {
        "enabled": "1",
        "action": "pass",
        "interface": "opt1",
        "source_net": "opt1",
        "destination_net": "192.168.1.10",
    }
    value = {"vlan": 20, "gateway": "10.0.20.1/24", "dhcp": {"enabled": False}, "access": "custom"}
    collect_module.apply(cfg, Change(device="x", kind="network.set", value=value))
    assert [r["destination_net"] for r in router.on("opt1")] == ["192.168.1.10"]


def test_deletes_a_network(router, cfg):
    collect_module.apply(cfg, Change(device="x", kind="network.set", value=iot40()))
    devices = collect_module.apply(
        cfg, Change(device="x", kind="network.delete", value={"vlan": 40})
    )
    assert 40 not in networks(devices)
    assert "opt2" not in router.assigned
    assert not any(v["tag"] == "40" for v in router.vlans.values())
    assert not router.on("opt2")
    assert "opt2" not in router.kea["interfaces"].split(",")
    with pytest.raises(PluginError, match="LAN"):
        collect_module.apply(cfg, Change(device="x", kind="network.delete", value={"vlan": 1}))


def test_needs_opnsense_26_7(router, cfg):
    router.assignments_api = False
    assert not collect_module.collect(cfg)[0].networks
    with pytest.raises(PluginError, match=r"26\.7"):
        collect_module.apply(cfg, Change(device="x", kind="network.set", value=iot40()))


def test_fixes_and_frees_an_address(router, cfg):
    value = {"mac": "AA-BB-CC-00-00-01", "ip": "192.168.1.50", "name": "Living room TV"}
    devices = collect_module.apply(cfg, Change(device="x", kind="reservation.set", value=value))
    [r] = router.reservations.values()
    assert (r["subnet"], r["ip_address"], r["hw_address"], r["hostname"]) == (
        "s1",
        "192.168.1.50",
        "aa:bb:cc:00:00:01",
        "living-room-tv",
    )
    got = devices[0].dhcp_reservations
    assert [(x.mac, x.ip) for x in got] == [("aa:bb:cc:00:00:01", "192.168.1.50")]
    # Again with another address: the same reservation changes.
    collect_module.apply(
        cfg, Change(device="x", kind="reservation.set", value={**value, "ip": "192.168.1.60"})
    )
    assert [x["ip_address"] for x in router.reservations.values()] == ["192.168.1.60"]
    devices = collect_module.apply(
        cfg, Change(device="x", kind="reservation.delete", value={"mac": "aa:bb:cc:00:00:01"})
    )
    assert not router.reservations
    assert not devices[0].dhcp_reservations


def test_a_reservation_needs_dhcp_in_its_network(router, cfg):
    value = {"mac": "aa:bb:cc:00:00:01", "ip": "10.0.20.50"}
    with pytest.raises(PluginError, match="DHCP"):
        collect_module.apply(cfg, Change(device="x", kind="reservation.set", value=value))


def test_discovery_between_networks(router, cfg):
    lan = {
        "vlan": 1,
        "gateway": "192.168.1.1/24",
        "dhcp": {"enabled": True, "from": "192.168.1.100", "to": "192.168.1.199"},
        "access": "all",
        "mdns": True,
    }
    collect_module.apply(cfg, Change(device="x", kind="network.set", value=lan))
    # One network alone repeats nothing: the repeater waits for a second.
    assert router.mdns == {"enabled": "0", "interfaces": "lan"}
    devices = collect_module.apply(
        cfg, Change(device="x", kind="network.set", value=iot40(mdns=True))
    )
    assert router.mdns == {"enabled": "1", "interfaces": "lan,opt2"}
    assert networks(devices)[40].mdns is True
    collect_module.apply(cfg, Change(device="x", kind="network.set", value=iot40(mdns=False)))
    assert router.mdns == {"enabled": "0", "interfaces": "lan"}


def test_discovery_needs_the_repeater_plugin(router, cfg):
    router.mdns = None
    assert networks(collect_module.collect(cfg))[1].mdns is None
    with pytest.raises(PluginError, match="os-mdns-repeater"):
        collect_module.apply(cfg, Change(device="x", kind="network.set", value=iot40(mdns=True)))


def test_shared_rules_are_no_network_s_access(router, cfg):
    shared = {
        "enabled": "1",
        "action": "pass",
        "interface": "lan,opt1",
        "source_net": "",
        "destination_net": "any",
    }
    router.rules["floating"] = dict(shared)
    # A floating "pass any" serves both: VLAN 20 is not "all" for it.
    assert networks(collect_module.collect(cfg))[20].access == "custom"
    value = {"vlan": 20, "gateway": "10.0.20.1/24", "dhcp": {"enabled": False}, "access": "local"}
    collect_module.apply(cfg, Change(device="x", kind="network.set", value=value))
    collect_module.apply(cfg, Change(device="x", kind="network.delete", value={"vlan": 20}))
    # Neither the change nor the removal touched the rule the LAN still needs.
    assert router.rules["floating"] == shared


def test_a_missing_endpoint_is_named(router, cfg):
    router.kea["enabled"] = "0"  # dnsmasq, whose hosts this fake lacks
    value = {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.50"}
    with pytest.raises(PluginError, match="OPNsense has no /api/dnsmasq/settings/search_host"):
        collect_module.apply(cfg, Change(device="x", kind="reservation.set", value=value))


def test_a_reservation_skips_subnets_it_cannot_read(router, cfg):
    router.subnets = {"s0": {"subnet": "", "pools": ""}, **router.subnets}
    value = {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.50"}
    collect_module.apply(cfg, Change(device="x", kind="reservation.set", value=value))
    assert [r["subnet"] for r in router.reservations.values()] == ["s1"]


def test_names_become_descriptions_opnsense_accepts(router, cfg):
    collect_module.apply(
        cfg, Change(device="x", kind="network.set", value=iot40(name="Câmeras & IoT"))
    )
    assert router.assigned["opt2"]["descr"] == "C_meras_IoT"
    assert next(v for v in router.vlans.values() if v["tag"] == "40")["descr"] == "C_meras_IoT"
    router.posts.clear()
    collect_module.apply(
        cfg, Change(device="x", kind="network.set", value=iot40(name="Câmeras & IoT"))
    )
    assert "/api/interfaces/assignment/set_item/opt2" not in router.posts  # nothing to change
    collect_module.apply(cfg, Change(device="x", kind="network.set", value=iot40(name="2nd")))
    assert router.assigned["opt2"]["descr"] == "VLAN40_2nd"


def test_the_address_omini_uses_is_not_changed(router, cfg):
    value = {"vlan": 1, "gateway": "192.168.2.1/24", "dhcp": {"enabled": False}}
    with pytest.raises(PluginError, match="Omini reaches OPNsense at"):
        collect_module.apply(cfg, Change(device="x", kind="network.set", value=value))
    assert router.assigned["lan"]["ipaddr"] == "192.168.1.1/24"


def test_a_failed_new_network_is_undone(router, cfg):
    post = router.post

    def refuse_subnet(path, body):
        if path == "/api/kea/dhcpv4/add_subnet":
            return 200, {"result": "failed", "validations": {"subnet4.pools": "bad pool"}}
        return post(path, body)

    router.post = refuse_subnet
    vlans, assigned = dict(router.vlans), dict(router.assigned)
    with pytest.raises(PluginError, match="bad pool"):
        collect_module.apply(cfg, Change(device="x", kind="network.set", value=iot40()))
    # The VLAN and the interface it had created are gone; what was there stays.
    assert router.vlans == vlans and router.assigned == assigned
    assert router.kea["interfaces"] == "lan"
