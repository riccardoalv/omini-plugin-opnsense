"""port.enabled: an interface assignment turned on or off (OPNsense 26.7+)."""

import pytest
from omini_sdk import Change, PluginError
from test_networks import router  # noqa: F401  (the router fixture)

import omini_opnsense.collect as collect_module

OVERVIEW = "/api/interfaces/overview/interfaces_info/1"


@pytest.fixture
def fw(router, opnsense):  # noqa: F811
    """The overview follows the assignments after a reconfigure, as on a firewall."""
    post = router.post

    def follow(path, body):
        out = post(path, body)
        if path == "/api/interfaces/assignment/reconfigure":
            by_device = {a["if"]: a.get("enable") == "1" for a in router.assigned.values()}
            for row in opnsense.routes[OVERVIEW]["rows"]:
                if row.get("device") in by_device:
                    row["enabled"] = by_device[row["device"]]
        return out

    router.post = follow
    return router


def toggle(cfg, port, on):
    return collect_module.apply(cfg, Change(device="x", kind="port.enabled", port=port, value=on))


def ports(devices):
    return {i.name: i.enabled for i in devices[0].interfaces}


def test_disables_and_enables_a_port(fw, cfg):
    devices = toggle(cfg, "vtnet0_vlan20", False)
    assert fw.assigned["opt1"]["enable"] == "0"
    assert fw.posts[-2:] == [
        "/api/interfaces/assignment/set_item/opt1",
        "/api/interfaces/assignment/reconfigure",
    ]
    assert ports(devices)["vtnet0_vlan20"] is False
    devices = toggle(cfg, "vtnet0_vlan20", True)
    assert fw.assigned["opt1"]["enable"] == "1" and ports(devices)["vtnet0_vlan20"] is True
    # Already as asked: nothing is written.
    fw.posts.clear()
    toggle(cfg, "vtnet0_vlan20", True)
    assert not fw.posts


def test_never_disables_the_port_omini_comes_through(fw, cfg):
    with pytest.raises(PluginError, match="the address Omini reaches OPNsense at"):
        toggle(cfg, "igb1", False)  # the LAN holds 192.168.1.1, the configured address
    assert not fw.posts


def test_an_unassigned_port_is_refused(fw, cfg):
    with pytest.raises(PluginError, match="no interface assigned"):
        toggle(cfg, "igb2", True)


def test_needs_the_assignments_api(fw, cfg):
    fw.assignments_api = False
    with pytest.raises(PluginError, match=r"26\.7 or later"):
        toggle(cfg, "vtnet0_vlan20", False)


def test_a_port_that_stays_up_fails(fw, cfg, monkeypatch):
    monkeypatch.setattr(collect_module.nets.time, "sleep", lambda _s: None)
    sent = []

    def accept(path, body):  # accepted, never applied
        sent.append((path, body))
        return (200, {"result": "saved"})

    fw.post = accept
    with pytest.raises(
        PluginError, match=r"did not apply disabling vtnet0_vlan20: .* within 30 s \(undone\)$"
    ):
        toggle(cfg, "vtnet0_vlan20", False)
    # The interface is turned back on.
    assert sent[-2] == (
        "/api/interfaces/assignment/set_item/opt1",
        {"interface": {"enable": "1"}},
    )


def test_needs_a_boolean(fw, cfg):
    with pytest.raises(PluginError, match="true or false"):
        collect_module.apply(cfg, Change(device="x", kind="port.enabled", port="igb1", value="off"))
