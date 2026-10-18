"""OPNsense REST API client (HTTP basic auth with an API key/secret), on the
SDK's HTTP client: timeouts, retries, and errors that name the privilege a
refused endpoint needs."""

from __future__ import annotations

import json
from typing import Any

import httpx
from omini_sdk import PluginError
from omini_sdk.http import Client as HttpClient
from omini_sdk.http import Forbidden, NotFound

__all__ = ["ENDPOINT_PRIVILEGES", "Client", "Forbidden", "NotFound"]

# The privilege of each endpoint (as named in System → Access → Users), so a
# refusal names the one that is missing.
ENDPOINT_PRIVILEGES = {
    "/api/interfaces/vlan_settings/": "Interfaces: VLAN",
    "/api/interfaces/assignment/": "Interfaces: Assignments",
    "/api/interfaces/overview/": "Status: Interfaces",
    "/api/interfaces/lagg_settings/": "Interfaces: LAGG",
    "/api/kea/": "Services: DHCP: Kea(v4)",
    "/api/dnsmasq/": "Services: Dnsmasq DNS/DHCP: Settings",
    "/api/firewall/filter/": "Firewall: Rules",
    "/api/firewall/alias/": "Firewall: Alias",
    "/api/mdnsrepeater/": "Services: mDNS Repeater",
    "/api/unbound/": "Services: Unbound DNS: Edit Host and Domain Override",
    "/api/wol/": "Services: Wake on LAN",
    "/api/diagnostics/system/": "Lobby: Dashboard",
}


class Client(HttpClient):
    def __init__(
        self,
        url: str,
        key: str,
        secret: str,
        verify_tls: bool = False,
        timeout: float = 15,
        transport: httpx.BaseTransport | None = None,
    ):
        super().__init__(
            url,
            name="OPNsense",
            auth=(key, secret),
            verify_tls=verify_tls,
            timeout=timeout,
            user_agent="omini-plugin-opnsense",
            unauthorized="OPNsense rejected the API key or secret",
            forbidden_hint=ENDPOINT_PRIVILEGES,
            transport=transport,
        )

    def get(self, *paths: str, params: dict[str, Any] | None = None) -> Any:  # type: ignore[override]
        """GETs the first path that works. Several spellings are accepted
        because OPNsense privileges match the exact URL, and the dashboard ones
        changed from camelCase (up to 25.1) to snake_case (25.7+)."""
        forbidden: Forbidden | None = None
        for path in paths:
            try:
                return self.request("GET", path, params=params)
            except Forbidden as e:
                forbidden = e
            except NotFound:
                continue
        if forbidden:
            raise forbidden
        raise NotFound(f"OPNsense has no {paths[0]}", status=404, resource=paths[0])

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:  # type: ignore[override]
        """POSTs a change; OPNsense answers {"result": "failed", "validations": ...}
        when it refuses one, which is raised with its messages."""
        out = self.request("POST", path, json=body if body is not None else {})
        if isinstance(out, dict) and str(out.get("result", "")).lower() == "failed":
            problems = out.get("validations") or {}
            detail = "; ".join(f"{k}: {v}" for k, v in problems.items()) or str(out)
            raise PluginError(f"OPNsense refused {path}: {detail}")
        if isinstance(out, dict) and str(out.get("status", "")).lower() == "failed":
            raise PluginError(f"OPNsense could not apply {path}")
        return out

    def get_text(self, path: str) -> str:
        """GETs a file the API answers as is (not JSON), e.g. config.xml."""
        return self.text(path)

    def stream_second_event(self, path: str, timeout: float = 4) -> dict[str, Any] | None:
        """Reads a server-sent events stream until its second event. The first
        event of OPNsense's CPU stream is the average since boot."""
        events = 0
        try:
            with self.http.stream("GET", path, timeout=timeout) as r:
                if r.status_code == 403:
                    raise Forbidden(privilege=self.privilege("GET", path), resource=path)
                if r.status_code >= 400:
                    return None
                for line in r.iter_lines():
                    if not line.startswith("data:"):
                        continue
                    events += 1
                    if events == 2:
                        return json.loads(line[5:].strip())
        except (httpx.HTTPError, json.JSONDecodeError):
            return None
        return None
