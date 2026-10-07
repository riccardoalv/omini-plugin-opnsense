"""System health: load, swap, disks, temperatures and firmware updates."""

from omini_opnsense.collect import collect, load_avg, parse_time


def test_load_swap_disks_and_temperatures(opnsense, cfg):
    [fw] = collect(cfg)
    assert fw.load_avg == [0.12, 0.10, 0.08]
    assert fw.swap_pct == 25.0
    # One entry per ZFS pool (its datasets share the space), named after "/";
    # empty helpers such as devfs are left out.
    zfs_used = 3820572672 + 1157165440 + 2531328
    assert [(s.mount, s.device, s.fs_type, s.total_bytes, s.used_bytes) for s in fw.storage] == [
        ("/", "zroot", "zfs", zfs_used + 2832834560, zfs_used),
        ("/boot/efi", "/dev/gpt/efiboot0", "msdosfs", 268419072, 1327104),
    ]
    assert [(t.sensor, t.kind, t.celsius) for t in fw.temperatures] == [
        ("CPU 0", "cpu", 47.0),
        ("CPU 1", "cpu", 49.0),
        ("Zone", "board", 27.9),
    ]


def test_pending_firmware_updates(opnsense, cfg):
    [fw] = collect(cfg)
    f = fw.firmware
    assert (f.current, f.latest, f.update_available, f.updates, f.needs_reboot) == (
        "26.7.4",
        "26.7.5",
        True,
        3,
        True,
    )
    assert f.checked_at is not None and f.checked_at.isoformat() == "2026-10-07T02:54:18-04:00"


def test_never_checked_for_updates(opnsense, cfg):
    # As answered by a firewall where nobody pressed "Check for updates" yet.
    opnsense.routes["/api/core/firmware/status"] = {
        "status_msg": "Firmware status requires to check for update first.",
        "status": "none",
        "product": {"product_version": "26.7.5", "product_latest": "26.7.5", "product_check": None},
    }
    [fw] = collect(cfg)
    assert fw.firmware.current == "26.7.5"
    assert fw.firmware.update_available is None and fw.firmware.checked_at is None


def test_virtual_machine_without_sensors_or_firmware_privilege(opnsense, cfg):
    opnsense.routes["/api/diagnostics/system/system_temperature"] = []
    opnsense.forbidden = {"/api/core/firmware/"}
    [fw] = collect(cfg)
    assert fw.temperatures is None and fw.firmware is None
    assert fw.storage  # the rest still works


def test_parsers():
    assert load_avg("0.34, 0.35, 0.33") == [0.34, 0.35, 0.33]
    assert load_avg("") is None and load_avg(None) is None
    assert parse_time("Thu Oct 1 03:22:51 -04 2026") == "2026-10-01T03:22:51-04:00"
    assert parse_time("2026-10-01T03:22:51+00:00") == "2026-10-01T03:22:51+00:00"
    assert parse_time("yesterday") is None
