# omini-plugin-opnsense

[Omini](https://github.com/riccardoalv/omini) plugin for **OPNsense**, through its official REST API. Read-only: it never changes the firewall's configuration.

## What it reads

| Data | Used for |
|---|---|
| Interfaces: name, description, status, MAC, IPs, **link speed / media** (e.g. `2500Base-T <full-duplex>`), traffic and error counters | Ports of the firewall on the map, link speed, traffic |
| ARP table | Which IP and MAC are on which interface |
| DHCP leases — ISC, Kea and dnsmasq (whichever is in use) | Names of devices the network scan only knows by MAC |
| Hostname, version, CPU, memory, swap, load, disks, temperatures, uptime | Firewall health |
| Pending firmware updates (from the last check made in OPNsense) | Firewall health |
| Gateways: status, latency, loss | WAN uplinks up/down |

Works with OPNsense 24.7 and later.

## Install

OPNsense is in Omini's plugin catalog: **Integrations → Add → OPNsense** installs it and opens its form (or **Settings → Plugins → Available**). It can also be installed from its address, `https://github.com/riccardoalv/omini-plugin-opnsense`.

## Create the API user in OPNsense

Use a dedicated user with only the privileges Omini needs, as the [OPNsense docs](https://docs.opnsense.org/development/how-tos/api.html) recommend:

1. **System → Access → Users → Add**: user `omini`, a random password (it is never used), and give it these privileges (*Effective Privileges*):

   | Privilege | For |
   |---|---|
   | Lobby: Dashboard | hostname, version, CPU, memory, swap, load, disks, temperatures, uptime (**required**) |
   | Status: Interfaces | ports, link speed, IPs, counters |
   | Reporting: Traffic | traffic counters of VLANs and other virtual interfaces |
   | Diagnostics: ARP Table | ARP table |
   | Status: DHCP leases | leases of ISC DHCP (on 26.1+: *Services: ISC DHCPv4: Leases*) |
   | Services: DHCP: Kea(v4) | leases of Kea, if you use it |
   | Services: Dnsmasq DNS/DHCP: Settings | leases of dnsmasq (the default DHCP server since 25.7) |
   | System: Gateways | gateway status |
   | System: Firmware | pending updates (Omini never starts a check or an update) |
   | **System: Deny config write** | **recommended**: some of the privileges above also allow changes; this one blocks configuration writes |

2. Edit the user again and, under **API keys**, click **+**: OPNsense downloads a file with the **key** and the **secret**.
3. In Omini, fill in the firewall address (e.g. `https://192.168.1.1`), the key and the secret, and click **Test connection**: it tells you which privileges are missing, if any.

OPNsense uses a self-signed certificate by default, so *Verify the TLS certificate* is off by default; turn it on if your firewall has a trusted certificate.

## Known limitations

- **PPPoE WANs:** OPNsense's API does not say which port carries a PPPoE link. The plugin uses the only VLAN with no role assigned (e.g. `vlan0.2000` for an ISP that tags PPPoE), else a port described as "WAN". When neither is found, the WAN shows no link speed (never a wrong one).
- **Traffic** is the average between two collections (every minute by default), not an instantaneous value.

## Development

The plugin uses [uv](https://docs.astral.sh/uv/) and expects the Omini repository next to it (the SDK is in `../omini/sdk/python`):

```bash
uv run pytest          # tests, against recorded OPNsense answers (tests/fixtures)
uv run ruff check .    # lint
uv run ruff format .   # format
```

Run it from a local Omini without installing it: `OMINI_PLUGIN_DIRS=../omini-plugin-opnsense make run` in the Omini repository; every collection uses the current code.

## License

MIT
