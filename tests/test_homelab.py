"""Local DNS names, Wake-on-LAN, pausing a device's internet, backups and link
aggregations, against a stateful fake of the OPNsense API."""

import json

import httpx
import pytest
from omini_sdk import Change, PluginError
from test_networks import Router

import omini_opnsense.collect as collect_module
from omini_opnsense import backup as backups

CONFIG_XML = """<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>opnsense</hostname>
    <domain>localdomain</domain>
  </system>
  <revision>
    <username>root@192.168.1.10</username>
    <time>{time}</time>
    <description>/api/unbound/settings/add_host_override made changes</description>
  </revision>
  <unbound>{hosts}</unbound>
</opnsense>
"""


class Firewall(Router):
    """Router plus Unbound, dnsmasq, os-wol, aliases that change, states and backups."""

    def __init__(self):
        super().__init__()
        self.unbound_on = True
        self.overrides = {
            "h1": {
                "enabled": "1",
                "hostname": "printer",
                "domain": "localdomain",
                "rr": "A (IPv4 address)",
                "server": "192.168.1.30",
                "description": "set by hand",
            },
            "h2": {
                "enabled": "1",
                "hostname": "mail",
                "domain": "localdomain",
                "rr": "MX (Mail server)",
                "server": "",
                "description": "",
            },
        }
        self.dnsmasq = {"enable": "0", "port": "0", "domain": "lan"}
        self.hosts = {}
        self.wol = True
        self.woken = []
        self.killed = []
        self.arp_rows = None
        self.saves = 0
        self.laggs = {}

    def get(self, path):
        if path == "/api/unbound/settings/get":
            return 200, {"unbound": {"general": {"enabled": "1" if self.unbound_on else "0"}}}
        if path == "/api/unbound/settings/search_host_override":
            return 200, self.search(self.overrides)
        if path == "/api/dnsmasq/settings/get":
            return 200, {"dnsmasq": dict(self.dnsmasq)}
        if path == "/api/dnsmasq/settings/search_host":
            return 200, self.search(self.hosts)
        if path == "/api/diagnostics/interface/search_arp" and self.arp_rows is not None:
            return 200, {"rows": self.arp_rows}
        if path == "/api/diagnostics/interface/get_ndp":
            return 200, [
                {"mac": "AA:BB:CC:00:00:01", "ip": "2001:db8:1::50", "intf": "bridge0"},
                {"mac": "aa:bb:cc:00:00:01", "ip": "fe80::1:50", "intf": "bridge0"},
                {"mac": "aa:bb:cc:00:00:09", "ip": "2001:db8:1::99", "intf": "bridge0"},
            ]
        if path == "/api/interfaces/lagg_settings/search_item":
            return 200, self.search(self.laggs)
        if path == "/api/core/backup/download/this":
            hosts = "".join(
                f"<host><hostname>{h['hostname']}</hostname><server>{h['server']}</server></host>"
                for h in self.overrides.values()
            )
            self.saves += 1
            return 200, CONFIG_XML.format(time=1_760_000_000 + self.saves, hosts=hosts)
        return super().get(path)

    def post(self, path, body):
        last = path.rsplit("/", 1)[-1]
        if path == "/api/unbound/settings/add_host_override":
            self.overrides[self.uuid()] = body["host"]
        elif path.startswith("/api/unbound/settings/set_host_override/"):
            self.overrides[last].update(body["host"])
        elif path.startswith("/api/unbound/settings/del_host_override/"):
            del self.overrides[last]
        elif path == "/api/dnsmasq/settings/add_host":
            self.hosts[self.uuid()] = body["host"]
        elif path.startswith("/api/dnsmasq/settings/set_host/"):
            self.hosts[last].update(body["host"])
        elif path.startswith("/api/dnsmasq/settings/del_host/"):
            del self.hosts[last]
        elif path == "/api/wol/wol/set":
            if not self.wol:
                return 404, {"errorMessage": "Endpoint not found"}
            self.woken.append(body["wake"])
            return 200, {"status": "OK"}
        elif path.startswith("/api/firewall/alias/set_item/"):
            self.aliases[last].update(body["alias"])
        elif path.startswith("/api/firewall/alias/del_item/"):
            if any(r.get("source_net") == self.aliases[last]["name"] for r in self.rules.values()):
                return 200, {"result": "failed", "validations": {"alias": "in use"}}
            del self.aliases[last]
        elif path.startswith("/api/firewall/filter/toggle_rule/"):
            uuid, enabled = path.split("/")[-2:]
            self.rules[uuid]["enabled"] = enabled
            return 200, {"result": "Disabled" if enabled == "0" else "Enabled", "changed": True}
        elif path == "/api/diagnostics/firewall/kill_states":
            self.killed.append(body["filter"])
            return 200, {"result": "ok", "dropped_states": 3}
        else:
            return super().post(path, body)
        return 200, {"result": "saved"}

    def alias(self, name):
        return next((a for a in self.aliases.values() if a["name"] == name), None)

    def paused_alias(self):
        return self.alias("omini_paused_mac")


@pytest.fixture
def fw(opnsense):
    f = Firewall()
    fallback = opnsense.handler

    def handler(request: httpx.Request) -> httpx.Response:
        if any(request.url.path.startswith(p) for p in opnsense.forbidden):
            return httpx.Response(403)
        body = json.loads(request.content) if request.content else None
        out = f.handle(request.method, request.url.path, body)
        if out is None:
            return fallback(request)
        if isinstance(out[1], str):
            return httpx.Response(out[0], text=out[1], headers={"content-type": "text/xml"})
        return httpx.Response(out[0], json=out[1])

    opnsense.handler = handler
    collect_module.Client.keywords["transport"] = httpx.MockTransport(handler)
    return f


def apply(cfg, kind, value):
    return collect_module.apply(cfg, Change(device="x", kind=kind, value=value))


def names(devices):
    return {(r.name, r.ip) for r in devices[0].dns_records or []}


# --- DNS ------------------------------------------------------------------------


def test_reads_the_local_names_and_domain(fw, cfg):
    [dev] = collect_module.collect(cfg)
    # The system's domain; A records only (the MX is not a name of a device).
    assert dev.dns_domain == "localdomain"
    assert names([dev]) == {("printer.localdomain", "192.168.1.30")}


def test_sets_changes_and_removes_a_name_in_unbound(fw, cfg):
    devices = apply(cfg, "dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.20"})
    assert ("nas.home.arpa", "192.168.1.20") in names(devices)
    [new] = [h for h in fw.overrides.values() if h["hostname"] == "nas"]
    assert (new["domain"], new["rr"], new["description"]) == ("home.arpa", "A", "Omini")
    assert "/api/unbound/service/reconfigure" in fw.posts

    # The same name with another address: the same override changes.
    devices = apply(cfg, "dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.21"})
    assert [h["server"] for h in fw.overrides.values() if h["hostname"] == "nas"] == [
        "192.168.1.21"
    ]
    devices = apply(cfg, "dns.delete", {"name": "nas.home.arpa"})
    assert not any(n == "nas.home.arpa" for n, _ in names(devices))
    # A name that is not there is already removed.
    apply(cfg, "dns.delete", {"name": "nas.home.arpa"})


def test_a_name_without_domain_takes_the_firewalls(fw, cfg):
    devices = apply(cfg, "dns.set", {"name": "nas", "ip": "192.168.1.20"})
    assert ("nas.localdomain", "192.168.1.20") in names(devices)


def test_names_in_dnsmasq(fw, cfg):
    fw.unbound_on = False
    fw.dnsmasq.update(enable="1", port="")
    fw.hosts["r1"] = {
        "host": "tv",
        "domain": "",
        "ip": "192.168.1.40",
        "hwaddr": "aa:bb:cc:00:00:02",
    }
    devices = apply(cfg, "dns.set", {"name": "nas.lan", "ip": "192.168.1.20"})
    assert names(devices) == {("nas.lan", "192.168.1.20"), ("tv.localdomain", "192.168.1.40")}
    assert any(h["host"] == "nas" and h["descr"] == "Omini" for h in fw.hosts.values())
    assert "/api/dnsmasq/service/reconfigure" in fw.posts
    apply(cfg, "dns.delete", {"name": "nas.lan"})
    assert [h["host"] for h in fw.hosts.values()] == ["tv"]
    # The TV's name is its fixed address too: removing it would free the address.
    with pytest.raises(PluginError, match="fixed address"):
        apply(cfg, "dns.delete", {"name": "tv.localdomain"})


def test_no_dns_server(fw, cfg):
    fw.unbound_on = False
    assert not collect_module.collect(cfg)[0].dns_records
    with pytest.raises(PluginError, match="Unbound nor dnsmasq"):
        apply(cfg, "dns.set", {"name": "nas.lan", "ip": "192.168.1.20"})


def test_dns_needs_its_privilege(fw, opnsense, cfg):
    opnsense.forbidden.add("/api/unbound/")
    assert not collect_module.collect(cfg)[0].dns_records  # quiet: not everyone uses it
    with pytest.raises(PluginError, match="Unbound DNS"):
        apply(cfg, "dns.set", {"name": "nas.lan", "ip": "192.168.1.20"})


# --- Wake-on-LAN ------------------------------------------------------------------


def test_wakes_on_the_network_that_holds_the_address(fw, cfg):
    apply(cfg, "wol.send", {"mac": "AA-BB-CC-00-00-09", "ip": "10.0.20.50"})
    apply(cfg, "wol.send", {"mac": "aa:bb:cc:00:00:0a"})
    assert fw.woken == [
        {"interface": "opt1", "mac": "aa:bb:cc:00:00:09"},
        {"interface": "lan", "mac": "aa:bb:cc:00:00:0a"},
    ]
    with pytest.raises(PluginError, match="no network"):
        apply(cfg, "wol.send", {"mac": "aa:bb:cc:00:00:0a", "ip": "172.20.0.5"})


def test_wake_names_the_privilege_it_lacks(fw, opnsense, cfg):
    # The interfaces are read first: their privilege is the one missing.
    opnsense.forbidden.add("/api/interfaces/overview/")
    with pytest.raises(PluginError, match="Status: Interfaces"):
        apply(cfg, "wol.send", {"mac": "aa:bb:cc:00:00:09"})


def test_wake_needs_os_wol(fw, cfg):
    fw.wol = False
    with pytest.raises(PluginError, match="os-wol"):
        apply(cfg, "wol.send", {"mac": "aa:bb:cc:00:00:09"})


# --- pausing the internet ---------------------------------------------------------

TV = {"mac": "aa:bb:cc:00:00:01", "ips": ["192.168.1.50"], "name": "Living room TV"}
CONSOLE = {"mac": "aa:bb:cc:00:00:02", "ips": ["10.0.20.60", "fd00::6"], "name": "Console (kids)"}


def pause_rules(fw, alias="omini_paused_mac"):
    return [r for r in fw.rules.values() if r["source_net"] == alias]


def test_pauses_and_resumes_devices(fw, cfg):
    devices = apply(cfg, "pause.set", TV)
    assert [(p.mac, p.ips, p.name) for p in devices[0].paused] == [
        ("aa:bb:cc:00:00:01", ["192.168.1.50"], "Living room TV")
    ]
    # A MAC alias: OPNsense finds the device's IPv4 and IPv6 addresses itself.
    alias = fw.paused_alias()
    assert (alias["type"], alias["content"]) == ("mac", "aa:bb:cc:00:00:01")
    assert alias["description"] == "Omini paused: aa:bb:cc:00:00:01 192.168.1.50 (Living room TV)"
    # One rule per LAN-side network, before the others, IPv4 and IPv6, to
    # anything not local.
    rules = pause_rules(fw)
    assert sorted(r["interface"] for r in rules) == ["lan", "opt1"]
    assert all(
        (r["action"], r["ipprotocol"], r["destination_net"], r["destination_not"], r["sequence"])
        == ("block", "inet46", "omini_local", "1", "1")
        for r in rules
    )
    # Its own networks stay reachable: private IPv4, link-local, ULA, multicast
    # and the LAN's IPv6 network.
    local = fw.alias("omini_local")
    assert (local["type"], local["content"].split("\n")) == (
        "network",
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fe80::/10",
            "fc00::/7",
            "ff00::/8",
            "fd00::/64",
        ],
    )
    # The connections it had open are cut, IPv6 ones (from the NDP table) too.
    assert fw.killed == ["192.168.1.50", "2001:db8:1::50"]
    # The pause rule is no network's access: the LAN is still "whole network".
    assert {n.vlan: n.access for n in devices[0].networks}[1] == "all"

    devices = apply(cfg, "pause.set", CONSOLE)
    assert {p.mac: p.ips for p in devices[0].paused} == {
        "aa:bb:cc:00:00:01": ["192.168.1.50"],
        "aa:bb:cc:00:00:02": ["10.0.20.60"],  # its IPv6 is the MAC alias's job
    }
    assert fw.paused_alias()["content"] == "aa:bb:cc:00:00:01\naa:bb:cc:00:00:02"
    assert len(pause_rules(fw)) == 2  # not added again

    # The TV got another address: its entry is replaced.
    devices = apply(cfg, "pause.set", {**TV, "ips": ["192.168.1.51"]})
    assert {p.mac: p.ips for p in devices[0].paused}["aa:bb:cc:00:00:01"] == ["192.168.1.51"]

    devices = apply(cfg, "pause.delete", {"mac": TV["mac"]})
    assert [p.mac for p in devices[0].paused] == ["aa:bb:cc:00:00:02"]
    assert fw.paused_alias()["content"] == "aa:bb:cc:00:00:02"
    assert len(pause_rules(fw)) == 2
    devices = apply(cfg, "pause.delete", {"mac": CONSOLE["mac"]})
    assert not devices[0].paused
    # Everything the pause added is gone.
    assert not pause_rules(fw)
    assert fw.paused_alias() is None and fw.alias("omini_local") is None
    # Resuming a device that is not paused changes nothing.
    posts = len(fw.posts)
    apply(cfg, "pause.delete", {"mac": CONSOLE["mac"]})
    assert not [p for p in fw.posts[posts:] if "/firewall/" in p]


def test_the_lans_public_ipv6_prefix_stays_reachable(fw, opnsense, cfg):
    """The ISP's prefix on the LAN (SLAAC, temporary addresses): the paused
    device loses the internet over IPv6, not the router or its neighbours."""
    rows = opnsense.routes["/api/interfaces/overview/interfaces_info/1"]["rows"]
    lan = next(r for r in rows if r["identifier"] == "lan")
    lan["ipv6"] = [*lan["ipv6"], {"ipaddr": "2804:1128:bd7c:8800::1/64"}]
    apply(cfg, "pause.set", TV)
    content = fw.alias("omini_local")["content"].split("\n")
    assert "2804:1128:bd7c:8800::/64" in content
    assert not any(c.startswith("fe80::") and c != "fe80::/10" for c in content)
    # The rule covers both families: an IPv6 address of the TV (not known to
    # Omini) matches the MAC alias and is blocked toward the internet.
    assert {r["ipprotocol"] for r in pause_rules(fw)} == {"inet46"}


def test_an_older_ipv4_pause_moves_to_the_mac_alias(fw, cfg):
    """0.5.0 paused by IPv4 address only: the next pause or resume migrates it."""
    fw.aliases["old"] = {
        "enabled": "1",
        "name": "omini_paused",
        "type": "host",
        "content": "192.168.1.50",
        "description": "Omini paused: aa:bb:cc:00:00:01 192.168.1.50 (TV)",
    }
    for ifname in ("lan", "opt1"):
        fw.rules[f"old-{ifname}"] = {
            "enabled": "1",
            "action": "block",
            "interface": ifname,
            "ipprotocol": "inet",
            "source_net": "omini_paused",
            "destination_net": "omini_private",
            "destination_not": "1",
            "sequence": "1",
        }
    [dev] = collect_module.collect(cfg)
    assert [(p.mac, p.ips) for p in dev.paused] == [("aa:bb:cc:00:00:01", ["192.168.1.50"])]
    devices = apply(cfg, "pause.set", CONSOLE)
    assert {p.mac for p in devices[0].paused} == {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}
    assert fw.alias("omini_paused") is None and not pause_rules(fw, "omini_paused")
    assert fw.paused_alias()["content"] == "aa:bb:cc:00:00:01\naa:bb:cc:00:00:02"
    assert len(pause_rules(fw)) == 2


def test_an_older_ipv4_pause_still_resumes(fw, cfg):
    fw.aliases["old"] = {
        "enabled": "1",
        "name": "omini_paused",
        "type": "host",
        "content": "192.168.1.50",
        "description": "Omini paused: aa:bb:cc:00:00:01 192.168.1.50 (TV)",
    }
    fw.rules["old-lan"] = {
        "enabled": "1",
        "action": "block",
        "interface": "lan",
        "ipprotocol": "inet",
        "source_net": "omini_paused",
        "destination_net": "omini_private",
        "destination_not": "1",
    }
    devices = apply(cfg, "pause.delete", {"mac": "aa:bb:cc:00:00:01"})
    assert not devices[0].paused
    assert not pause_rules(fw, "omini_paused") and not pause_rules(fw)
    assert fw.alias("omini_paused") is None and fw.paused_alias() is None


def test_a_pause_survives_its_network_access_change(fw, cfg):
    apply(cfg, "pause.set", TV)
    lan = {
        "vlan": 1,
        "gateway": "192.168.1.1/24",
        "dhcp": {"enabled": True, "from": "192.168.1.100", "to": "192.168.1.199"},
        "access": "internet",
    }
    apply(cfg, "network.set", lan)
    assert any(r["interface"] == "lan" for r in pause_rules(fw))


def test_pause_refusals(fw, cfg):
    with pytest.raises(PluginError, match="IPv4"):
        apply(cfg, "pause.set", {"mac": TV["mac"], "ips": ["fd00::1"]})
    with pytest.raises(PluginError, match="MAC"):
        apply(cfg, "pause.set", {"mac": "nope", "ips": ["192.168.1.5"]})
    # The firewall's own LAN port.
    with pytest.raises(PluginError, match="firewall itself"):
        apply(cfg, "pause.set", {"mac": "00:0d:b9:aa:bb:cc", "ips": ["192.168.1.1"]})
    assert fw.paused_alias() is None


def test_pause_names_the_vlan_privilege(fw, opnsense, cfg):
    opnsense.forbidden.add("/api/interfaces/vlan_settings/")
    with pytest.raises(PluginError, match="Interfaces: VLAN"):
        apply(cfg, "pause.set", TV)


def test_description_round_trip():
    from omini_opnsense import pause

    items = [
        {"mac": "aa:bb:cc:00:00:01", "ips": ["192.168.1.50", "192.168.1.51"], "name": "TV"},
        {"mac": "aa:bb:cc:00:00:02", "ips": ["10.0.0.2"], "name": None},
    ]
    text = pause.describe(items)
    assert text == "Omini paused: aa:bb:cc:00:00:01 192.168.1.50 192.168.1.51 (TV); " + (
        "aa:bb:cc:00:00:02 10.0.0.2"
    )
    assert pause.parse(text) == items
    assert pause.clean_name("Console (kids); 2") == "Console kids 2"


# --- backups ------------------------------------------------------------------------


def test_backup_is_config_xml_without_the_revision(fw, cfg):
    [first] = collect_module.backup(cfg)
    [second] = collect_module.backup(cfg)
    assert first.format == "xml" and first.device == collect_module.collect(cfg)[0].key
    assert "<revision>" not in first.content and "<hostname>printer</hostname>" in first.content
    # The download's revision time changed; the configuration did not.
    assert first.content == second.content
    apply(cfg, "dns.set", {"name": "nas.localdomain", "ip": "192.168.1.20"})
    [third] = collect_module.backup(cfg)
    assert third.content != first.content


def test_backup_needs_its_privilege(fw, opnsense, cfg):
    opnsense.forbidden.add("/api/core/backup/")
    with pytest.raises(PluginError, match="Backup"):
        collect_module.backup(cfg)


def test_clean_keeps_everything_else():
    raw = "<opnsense>\r\n  <a>1</a>\r\n  <revision><time>1</time></revision>\r\n</opnsense>"
    assert backups.clean(raw) == "<opnsense>\n  <a>1</a>\n</opnsense>\n"


# --- link aggregations ----------------------------------------------------------------


def test_link_aggregation_members(fw, opnsense, cfg):
    rows = opnsense.routes["/api/interfaces/overview/interfaces_info/1"]["rows"]
    rows.append(
        {
            "device": "lagg0",
            "identifier": "",
            "description": "Unassigned Interface",
            "status": "up",
            "macaddr": "00:0d:b9:aa:bb:01",
            "laggport": {"igb2": {"flags": ["active"]}},  # only the members that are up
        }
    )
    fw.laggs["l1"] = {"laggif": "lagg0", "members": "igb2,igb3", "proto": "lacp"}
    rows.append({"device": "igb3", "identifier": "", "status": "no carrier"})
    ports = {i.name: i for i in collect_module.collect(cfg)[0].interfaces}
    assert ports["lagg0"].type == "lag"
    assert ports["lagg0"].members == ["igb2", "igb3"]
    assert (ports["igb2"].lag, ports["igb3"].lag, ports["igb1"].lag) == ("lagg0", "lagg0", None)


def test_a_change_the_firewall_did_not_keep_fails(fw, cfg, monkeypatch):
    from omini_opnsense import networks

    monkeypatch.setattr(networks.time, "sleep", lambda _s: None)
    monkeypatch.setattr(fw, "overrides", {})
    real_post = fw.post

    def ignore_overrides(path, body):
        if "host_override" in path:
            return 200, {"result": "saved"}  # answers saved, keeps nothing
        return real_post(path, body)

    monkeypatch.setattr(fw, "post", ignore_overrides)
    with pytest.raises(PluginError, match=r"did not apply the name nas\.lan"):
        apply(cfg, "dns.set", {"name": "nas.lan", "ip": "192.168.1.20"})


# --- blocks set by hand -------------------------------------------------------------


def hand_block(fw, source, description):
    uuid = fw.uuid()
    fw.rules[uuid] = {
        "enabled": "1",
        "action": "block",
        "interface": "lan",
        "direction": "in",
        "ipprotocol": "inet46",
        "source_net": source,
        "destination_net": "any",
        "description": description,
    }
    return uuid


def test_blocks_set_by_hand_show_as_paused_and_resume(fw, cfg):
    fw.arp_rows = [
        {"ip": "192.168.1.77", "mac": "aa:bb:cc:00:00:77", "intf": "bridge0"},
        {"ip": "192.168.1.78", "mac": "aa:bb:cc:00:00:78", "intf": "bridge0"},
        {"ip": "192.168.1.79", "mac": "aa:bb:cc:00:00:79", "intf": "bridge0"},
    ]
    fw.aliases[fw.uuid()] = {
        "name": "kids",
        "type": "host",
        "content": "192.168.1.78\n192.168.1.79",
    }
    alone = hand_block(fw, "192.168.1.77", "Block the PC")
    shared = hand_block(fw, "kids", "Kids at night")
    # Not simple: a port, a network, a pass rule. They are no pauses.
    fw.rules[fw.uuid()] = {**fw.rules[alone], "destination_port": "443", "description": "web only"}
    fw.rules[fw.uuid()] = {
        **fw.rules[alone],
        "source_net": "192.168.1.0/24",
        "description": "the LAN",
    }
    fw.rules[fw.uuid()] = {**fw.rules[alone], "action": "pass", "description": "allowed"}
    [dev] = collect_module.collect(cfg)
    assert {(p.mac, tuple(p.ips or []), p.rule) for p in dev.paused} == {
        ("aa:bb:cc:00:00:77", ("192.168.1.77",), "Block the PC"),
        ("aa:bb:cc:00:00:78", ("192.168.1.78",), "Kids at night"),
        ("aa:bb:cc:00:00:79", ("192.168.1.79",), "Kids at night"),
    }
    # Resuming one blocked alone turns its rule off.
    devices = apply(cfg, "pause.delete", {"mac": "aa:bb:cc:00:00:77"})
    assert fw.rules[alone]["enabled"] == "0"
    assert "aa:bb:cc:00:00:77" not in {p.mac for p in devices[0].paused or []}
    # A rule blocking several devices is the user's to change.
    with pytest.raises(PluginError, match="blocks other devices too"):
        apply(cfg, "pause.delete", {"mac": "aa:bb:cc:00:00:78"})
    assert fw.rules[shared]["enabled"] == "1"
    # Omini's own pause is no block set by hand.
    apply(cfg, "pause.set", TV)
    [dev] = collect_module.collect(cfg)
    assert {p.mac: p.rule for p in dev.paused}["aa:bb:cc:00:00:01"] is None
