# omini-plugin-opnsense

[Omini](https://github.com/riccardoalv/omini) plugin for **OPNsense**, through its official REST API. It reads the firewall, keeps the versions of its configuration, sets local DNS names and wakes devices; on OPNsense 26.7 or later it also manages the networks of your VLANs from Omini (each VLAN's interface and gateway, its DHCP range and its access rules), fixed addresses and pausing a device's internet. It changes nothing else.

## What it reads

| Data | Used for |
|---|---|
| Interfaces: name, description, status, enabled or disabled, MAC, IPs, **link speed / media** (e.g. `2500Base-T <full-duplex>`), traffic and error counters | Ports of the firewall on the map, link speed, traffic |
| ARP table | Which IP and MAC are on which interface |
| NDP table (IPv6 neighbours) | Which IPv6 address belongs to which MAC, so traffic over IPv6 reaches the right device |
| DHCP leases — ISC, Kea and dnsmasq (whichever is in use) | Names of devices the network scan only knows by MAC |
| Hostname, version, CPU, memory (installed, used and %), swap, load, disks, temperatures, uptime | Firewall health |
| Pending firmware updates (from the last check made in OPNsense) | Firewall health |
| Gateways: status, latency, loss | WAN uplinks up/down |
| VLANs: id, description, parent port, subnet; the VLAN id of each VLAN interface | VLANs of the network |
| SFP/QSFP modules: vendor, part and serial number, type, temperature, voltage, RX power and laser bias (when the NIC driver reads the module) | Health of optical links |
| Services: running or stopped | A service that stopped |
| VPN peers — WireGuard, OpenVPN and IPsec: endpoint, tunnel address, connected, last handshake (WireGuard), traffic | VPN tunnels up/down |
| DHCP pool usage (Kea and dnsmasq ranges, counted against the active leases) | A pool running out of addresses |
| Firewall state table: current entries and limit | A state table filling up |
| Networks (26.7+): each VLAN's interface, gateway, DHCP range and access rules; the LAN is VLAN 1 | The VLANs tab: a VLAN as a whole network |
| Link aggregations (LAGG): each member port and its `lagg` (members that are down too) | LAGs on the map |
| Local DNS names: Unbound host overrides (A records) and their host aliases (when the API user may read them), or dnsmasq hosts when dnsmasq is the DNS server; the local domain (the system's domain, else dnsmasq's) | Names of devices with a fixed address |
| Paused devices (the `omini_paused_mac` alias, and simple block rules set by hand) | The pause mark on the map |
| The configuration, `config.xml` (on demand, not every round) | The device's configuration history and its differences |

## What it changes

Only when you create, change or delete a VLAN's network in Omini (the map's menu → **VLANs**), and only on OPNsense 26.7 or later, where interface assignments came to the API:

- **Network** (`network.set`): the VLAN on the port toward your switches (a bridge's physical member), its interface with the gateway address, its DHCP range (Kea when it is on, else dnsmasq; the gateway is handed out as DNS) and its access rules:
  - **Internet only**: DNS to the gateway, nothing to the private ranges (an alias `omini_private`: 10/8, 172.16/12, 192.168/16), everything else;
  - **Whole network**: everything;
  - **No internet**: DNS to the gateway only.

  Picking one of them replaces the rules of that interface (its own: a floating rule, on several interfaces, is no network's access and is never removed); rules set by hand that are none of them show as **Custom** in Omini and are left as they are until you pick one. Rules Omini writes start with "Omini:".
- **Discovery between VLANs** (mDNS, part of `network.set`): the network joins or leaves the mDNS repeater of the **os-mdns-repeater** plugin (install it in System → Firmware → Plugins), which runs while two or more networks are in it.
- **Fixed addresses** (`reservation.set`, `reservation.delete`): a DHCP reservation (Kea or dnsmasq) for a device's MAC, from the device's panel in Omini.
- **Removing** it (`network.delete`): its rules, its DHCP, its discovery, its interface and its VLAN. Never the LAN.

Also, on any supported version:

- **Local DNS names** (`dns.set`, `dns.delete`): an Unbound host override (an A record, description "Omini") when Unbound is the DNS server, else a dnsmasq host; changing a name's address changes the same entry. Names set by hand are read too. A dnsmasq host that is also a fixed address (it has a MAC) is never removed by `dns.delete`: free the address instead.
- **Wake-on-LAN** (`wol.send`): the firewall sends the magic packet on the interface whose network holds the device's address (the LAN when it has none), through the **os-wol** plugin (install it in System → Firmware → Plugins). Without it, Omini says so.
- **Configuration backups**: Omini keeps the versions of `config.xml` (System → Configuration → Backups' download), without the `<revision>` stamp OPNsense writes on every save, so two backups differ only when the configuration did. It holds secrets (password hashes, keys): Omini stores it encrypted and never restores it.

And on 26.7 or later:

- **Pausing a device's internet** (`pause.set`, `pause.delete`), over IPv4 **and IPv6**: the device's MAC goes in a MAC-address alias `omini_paused_mac` (OPNsense resolves it to the device's IPv4 and IPv6 addresses from its ARP and NDP tables, so the changing IPv6 temporary/privacy addresses of SLAAC are covered too; its description keeps the IPv4 addresses and name Omini sent, e.g. `Omini paused: aa:bb:cc:dd:ee:ff 192.168.1.50 (TV)`). Each LAN-side interface gets one rule, first in its list (sequence 1), for IPv4+IPv6: block from `omini_paused_mac` to anything that is **not** `omini_local`, described "Omini: paused devices (no internet)". `omini_local` is a network alias with what the device still reaches: the private IPv4 ranges, IPv6 link-local (`fe80::/10`), ULA (`fc00::/7`) and multicast (`ff00::/8`), and the IPv6 networks of the LAN-side interfaces (e.g. the ISP's prefix on the LAN), refreshed at every pause. The firewall's own MACs are never paused. Its open IPv4 connections are cut (states killed), when the API user may. Resuming the last device removes the rules and both aliases. The pause rule is not part of a network's access (Internet only, Whole network…), and changing the access keeps it. A pause made by 0.5.0 or earlier (the IPv4 host alias `omini_paused` and its IPv4 rules) is moved to the MAC alias at the next pause or resume, and can be resumed as usual.
- **Blocks set by hand** show as paused too: an enabled block or reject rule, inbound, from hosts (IP addresses, MACs, or a host or MAC alias of them, resolved to devices through the ARP and NDP tables) to anything, with no ports or schedule. Omini shows the rule's description as the reason. Resuming such a device turns the rule off (`POST /api/firewall/filter/toggle_rule/<uuid>/0`, then apply) when it blocks that device alone; a rule that blocks several devices is refused, to be changed in OPNsense. Other rules (with ports, networks, schedules) are left as they are.

OPNsense saves every API change in its configuration; the plugin reads the firewall again until it serves the network as asked, and reports an error otherwise.

Works with OPNsense 24.7 and later.

## Install

OPNsense is in Omini's plugin catalog: **Integrations → Add → OPNsense** installs it and opens its form (or **Integrations → Plugin store → Available**). It can also be installed from its address, `https://github.com/riccardoalv/omini-plugin-opnsense`.

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
   | Interfaces: Assignments | the networks (26.7+); to change them too |
   | Firewall: Rules | the networks' access; to change it too |
   | Firewall: Alias | the `omini_private` alias of "Internet only" |
   | Services: mDNS Repeater | discovery between VLANs, if you use it |
   | Interfaces: LAGG | link aggregation members that are down (the ones up come with the interfaces) |
   | Services: Unbound DNS: Edit Host and Domain Override (and Services: Unbound DNS: General, to see that Unbound is on) | local DNS names, with Unbound |
   | Services: Dnsmasq DNS/DHCP: Settings | local DNS names, with dnsmasq as the DNS server |
   | Services: Wake on LAN | Wake-on-LAN (os-wol) |
   | Firewall: Alias, Firewall: Rules, Interfaces: Assignments, Interfaces: VLAN | pausing a device's internet (26.7+) |
   | Diagnostics: Show States (or Diagnostics: pfTop) | cutting a paused device's open connections (optional: without it the pause still applies to new connections) |
   | Diagnostics: NDP Table | the NDP table (IPv6 neighbours), and finding a paused device's IPv6 addresses to cut its open IPv6 connections (optional: without it there are no IPv6 neighbours, and IPv6 connections opened before the pause stay until they close) |
   | Diagnostics: Backup & Restore (System: Configuration: History on newer versions) | configuration backups (`config.xml`) |
   | **System: Deny config write** | only if Omini should **not** manage networks: it blocks every configuration write |

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
- **Paused devices** are blocked by their MAC, which OPNsense turns into addresses from its ARP and NDP tables: an address the firewall has not seen yet (a brand-new IPv6 temporary address) is blocked once OPNsense refreshes the alias (it does so periodically and whenever aliases are applied). A network created after a device was paused gets its pause rule at the next pause or resume.
- **Spanning tree** of bridges is not reported: the API has no per-port STP state.

## Not verified on hardware

These API shapes come from OPNsense's source and documentation, and are tested against an emulation, not a real firewall:

- Unbound host overrides: `search_host_override` rows with `hostname`, `domain`, `rr` (`A`, or `A (IPv4 address)` as the grid shows it) and `server`; `/api/unbound/settings/get` → `unbound.general.enabled`.
- Unbound host aliases: `search_host_alias` rows with `enabled`, `host` (the override's uuid, or its name as an older grid shows it), `hostname` and `domain` (empty: the override's). An alias is changed in OPNsense: `dns.set` and `dns.delete` refuse its name.
- dnsmasq as a DNS server: `/api/dnsmasq/settings/get` → `dnsmasq.enable`, `port` (0 = DNS off) and `domain`; hosts with `host`, `domain`, `ip`, `hwaddr`.
- os-wol: `POST /api/wol/wol/set` with `{"wake": {"interface": "lan", "mac": "…"}}`.
- Aliases: `set_item/{uuid}` and `del_item/{uuid}` with `mac` and `network` aliases whose `content` is newline separated; rules with `sequence`, `source_net` set to an alias and `destination_not`, and `ipprotocol: inet46`.
- Pausing over IPv6: that a `mac` alias used as a rule's source resolves to the device's IPv4 **and** IPv6 (NDP) addresses, including SLAAC temporary ones, soon enough after they appear; that the overview's `ipv6` rows of a tracked (delegated-prefix) LAN carry its global address with the prefix length; that a network alias mixes IPv4 and IPv6 networks in an `inet46` rule.
- `POST /api/diagnostics/firewall/kill_states` with `{"filter": "<ip>"}`, for the device's IPv4 addresses and the IPv6 ones the NDP table (`GET /api/diagnostics/interface/get_ndp`) has for its MAC: the firewall keeps a connection opened before the pause, and a phone keeps its IPv6 ones (to Google, say) open for long.
- `GET /api/core/backup/download/this` answering `config.xml`, and the privilege that grants it.
- `/api/interfaces/lagg_settings/search_item` rows with `laggif` and `members`.
- `GET /api/diagnostics/interface/get_ndp` answering a list of `{mac, ip, intf}` (or `{rows: [...]}`), and that the *Diagnostics: NDP Table* privilege grants it.

## API endpoints used

Reading is all `GET`; the changes are the `POST`s below ([API reference](https://docs.opnsense.org/development/api.html)). Where OPNsense renamed an endpoint from camelCase to snake_case, both spellings are tried.

| Endpoint | Data | Reference |
|---|---|---|
| `/api/diagnostics/system/system_information`, `system_resources`, `system_time`, `system_swap`, `system_disk`, `system_temperature`, `/api/diagnostics/cpu_usage/stream` | system and health | [diagnostics](https://docs.opnsense.org/development/api/core/diagnostics.html) |
| `/api/interfaces/overview/interfaces_info/1` | interfaces, VLAN ids, SFP modules | [interfaces](https://docs.opnsense.org/development/api/core/interfaces.html) |
| `/api/interfaces/vlan_settings/search_item` | VLANs | [interfaces](https://docs.opnsense.org/development/api/core/interfaces.html) |
| `/api/diagnostics/traffic/interface` | counters of virtual interfaces | [diagnostics](https://docs.opnsense.org/development/api/core/diagnostics.html) |
| `/api/diagnostics/interface/get_ndp` | NDP (IPv6 neighbours) | [diagnostics](https://docs.opnsense.org/development/api/core/diagnostics.html) |
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
| `/api/interfaces/assignment/search_item`, `add_item`, `set_item`, `del_item`, `reconfigure` | networks' interfaces (26.7+) | [interfaces](https://docs.opnsense.org/development/api/core/interfaces.html) |
| `/api/interfaces/vlan_settings/add_item`, `del_item`, `reconfigure` | networks' VLANs | [interfaces](https://docs.opnsense.org/development/api/core/interfaces.html) |
| `/api/kea/dhcpv4/get`, `set`, `add_subnet`, `set_subnet`, `del_subnet`, `/api/kea/service/reconfigure` | networks' DHCP (Kea) | [kea](https://docs.opnsense.org/development/api/core/kea.html) |
| `/api/dnsmasq/settings/add_range`, `set_range`, `del_range`, `/api/dnsmasq/service/reconfigure` | networks' DHCP (dnsmasq) | [dnsmasq](https://docs.opnsense.org/development/api/core/dnsmasq.html) |
| `/api/kea/dhcpv4/search_reservation`, `add_reservation`, `set_reservation`, `del_reservation`, `/api/dnsmasq/settings/search_host`, `add_host`, `set_host`, `del_host` | fixed addresses | [kea](https://docs.opnsense.org/development/api/core/kea.html), [dnsmasq](https://docs.opnsense.org/development/api/core/dnsmasq.html) |
| `/api/mdnsrepeater/settings/get`, `set`, `/api/mdnsrepeater/service/reconfigure` | discovery between VLANs | os-mdns-repeater |
| `/api/firewall/filter/search_rule`, `add_rule`, `del_rule`, `apply`, `/api/firewall/alias/search_item`, `add_item`, `reconfigure` | networks' access | [firewall](https://docs.opnsense.org/development/api/core/firewall.html) |
| `/api/interfaces/lagg_settings/search_item` | link aggregation members | [interfaces](https://docs.opnsense.org/development/api/core/interfaces.html) |
| `/api/unbound/settings/get`, `search_host_override`, `search_host_alias`, `add_host_override`, `set_host_override`, `del_host_override`, `/api/unbound/service/reconfigure` | local DNS names (Unbound) | [unbound](https://docs.opnsense.org/development/api/core/unbound.html) |
| `/api/dnsmasq/settings/get`, `search_host`, `add_host`, `set_host`, `del_host`, `/api/dnsmasq/service/reconfigure` | local DNS names (dnsmasq) | [dnsmasq](https://docs.opnsense.org/development/api/core/dnsmasq.html) |
| `/api/wol/wol/set` | Wake-on-LAN | [wol](https://docs.opnsense.org/development/api/plugins/wol.html) |
| `/api/firewall/alias/set_item`, `del_item`, `/api/firewall/filter/add_rule`, `del_rule`, `apply`, `/api/diagnostics/firewall/kill_states` | pausing a device's internet | [firewall](https://docs.opnsense.org/development/api/core/firewall.html) |
| `/api/core/backup/download/this` | configuration backups | [core](https://docs.opnsense.org/development/api/core/core.html) |

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
