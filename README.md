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
| VLANs: id, description, parent port, subnet; the VLAN id of each VLAN interface | VLANs of the network |
| SFP/QSFP modules: vendor, part and serial number, type, temperature, voltage, RX power and laser bias (when the NIC driver reads the module) | Health of optical links |
| Services: running or stopped | A service that stopped |
| VPN peers — WireGuard, OpenVPN and IPsec: endpoint, tunnel address, connected, last handshake (WireGuard), traffic | VPN tunnels up/down |
| DHCP pool usage (Kea and dnsmasq ranges, counted against the active leases) | A pool running out of addresses |
| Firewall state table: current entries and limit | A state table filling up |

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
   | Interfaces: VLAN | VLAN names and parent ports (without it, VLAN ids still come from the interfaces) |
   | Status: Services | services running or stopped |
   | Diagnostics: Firewall statistics | state table size and limit |
   | VPN: WireGuard: Status | WireGuard peers, if you use WireGuard |
   | Status: OpenVPN | OpenVPN connections, if you use OpenVPN |
   | Status: IPsec | IPsec tunnels, if you use IPsec |
   | **System: Deny config write** | **recommended**: some of the privileges above also allow changes; this one blocks configuration writes |

2. Edit the user again and, under **API keys**, click **+**: OPNsense downloads a file with the **key** and the **secret**.
3. In Omini, fill in the firewall address (e.g. `https://192.168.1.1`), the key and the secret, and click **Test connection**: it tells you which privileges are missing, if any (the VPN ones are not reported: only those who use a VPN need them).

DHCP pool usage needs no extra privilege: the Kea and dnsmasq privileges above also cover their ranges.

OPNsense uses a self-signed certificate by default, so *Verify the TLS certificate* is off by default; turn it on if your firewall has a trusted certificate.

## Known limitations

- **PPPoE WANs:** OPNsense's API does not say which port carries a PPPoE link. The plugin uses the only VLAN with no role assigned (e.g. `vlan0.2000` for an ISP that tags PPPoE), else a port described as "WAN". When neither is found, the WAN shows no link speed (never a wrong one).
- **Traffic** is the average between two collections (every minute by default), not an instantaneous value.
- **DHCP pools of ISC DHCP** are not reported: ISC keeps its ranges in the legacy configuration, which has no API. Kea and dnsmasq ranges are.
- **SFP modules:** OPNsense reads them from `ifconfig -v`, and only NICs whose driver reads the module's EEPROM report them. For a plain SFP/SFP+ module OPNsense keeps the identity, temperature and voltage; RX power and laser bias come only in the per-lane lines that QSFP modules print. Transmit power, wavelength and alarm thresholds are not in the API.
- **Services:** OPNsense lists only the services enabled in its configuration, so each one is reported as enabled; a disabled service is simply not listed.
- **WireGuard peers** count as connected after a handshake in the last 5 minutes, as in OPNsense's own status page; an idle peer without keepalive can show as not connected.

## API endpoints used

All `GET`, all read-only ([API reference](https://docs.opnsense.org/development/api.html)). Where OPNsense renamed an endpoint from camelCase to snake_case, both spellings are tried.

| Endpoint | Data | Reference |
|---|---|---|
| `/api/diagnostics/system/system_information`, `system_resources`, `system_time`, `system_swap`, `system_disk`, `system_temperature`, `/api/diagnostics/cpu_usage/stream` | system and health | [diagnostics](https://docs.opnsense.org/development/api/core/diagnostics.html) |
| `/api/interfaces/overview/interfaces_info/1` | interfaces, VLAN ids, SFP modules | [interfaces](https://docs.opnsense.org/development/api/core/interfaces.html) |
| `/api/interfaces/vlan_settings/search_item` | VLANs | [interfaces](https://docs.opnsense.org/development/api/core/interfaces.html) |
| `/api/diagnostics/traffic/interface` | counters of virtual interfaces | [diagnostics](https://docs.opnsense.org/development/api/core/diagnostics.html) |
| `/api/diagnostics/interface/search_arp` | ARP | [diagnostics](https://docs.opnsense.org/development/api/core/diagnostics.html) |
| `/api/diagnostics/firewall/pf_statistics/info`, `pf_statistics/memory` | state table entries and limit | [diagnostics](https://docs.opnsense.org/development/api/core/diagnostics.html) |
| `/api/dhcpv4/leases/search_lease`, `/api/kea/leases4/search`, `/api/dnsmasq/leases/search` | DHCP leases | [kea](https://docs.opnsense.org/development/api/core/kea.html), [dnsmasq](https://docs.opnsense.org/development/api/core/dnsmasq.html) |
| `/api/kea/dhcpv4/search_subnet`, `/api/dnsmasq/settings/search_range` | DHCP ranges | [kea](https://docs.opnsense.org/development/api/core/kea.html), [dnsmasq](https://docs.opnsense.org/development/api/core/dnsmasq.html) |
| `/api/routes/gateway/status` | gateways | [routes](https://docs.opnsense.org/development/api/core/routes.html) |
| `/api/core/firmware/status` | pending updates | [core](https://docs.opnsense.org/development/api/core/core.html) |
| `/api/core/service/search` | services | [core](https://docs.opnsense.org/development/api/core/core.html) |
| `/api/wireguard/service/show` | WireGuard peers | [wireguard](https://docs.opnsense.org/development/api/core/wireguard.html) |
| `/api/openvpn/service/search_sessions` | OpenVPN connections | [openvpn](https://docs.opnsense.org/development/api/core/openvpn.html) |
| `/api/ipsec/sessions/search_phase1` | IPsec tunnels | [ipsec](https://docs.opnsense.org/development/api/core/ipsec.html) |

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
