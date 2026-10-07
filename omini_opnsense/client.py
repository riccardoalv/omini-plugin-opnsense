"""Minimal OPNsense REST API client (HTTP basic auth with an API key/secret)."""

from __future__ import annotations

import json
from typing import Any

import httpx
from omini_sdk import PluginError


class Forbidden(Exception):
    """The API user lacks the privilege for an endpoint."""


class NotFound(Exception):
    """The endpoint does not exist (feature or plugin not installed)."""


class Client:
    def __init__(
        self,
        url: str,
        key: str,
        secret: str,
        verify_tls: bool = False,
        timeout: float = 15,
        transport: httpx.BaseTransport | None = None,
    ):
        url = url.strip().rstrip("/")
        if not url.startswith(("https://", "http://")):
            url = "https://" + url
        self.base = url
        self.http = httpx.Client(
            base_url=url,
            auth=(key, secret),
            verify=verify_tls,
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": "omini-plugin-opnsense"},
            transport=transport,
        )

    def close(self) -> None:
        self.http.close()

    def get(self, *paths: str, params: dict[str, Any] | None = None) -> Any:
        """GETs the first path that works. Several spellings are accepted
        because OPNsense privileges match the exact URL, and the dashboard ones
        changed from camelCase (up to 25.1) to snake_case (25.7+)."""
        forbidden: Forbidden | None = None
        for path in paths:
            try:
                return self._get(path, params)
            except Forbidden as e:
                forbidden = e
            except NotFound:
                continue
        if forbidden:
            raise forbidden
        raise NotFound(paths[0])

    def _get(self, path: str, params: dict[str, Any] | None) -> Any:
        try:
            r = self.http.get(path, params=params)
        except httpx.ConnectError as e:
            raise PluginError(f"cannot connect to {self.base}: {e}") from e
        except httpx.TimeoutException as e:
            raise PluginError(f"{self.base} did not answer in time") from e
        except httpx.HTTPError as e:
            raise PluginError(f"request to {self.base} failed: {e}") from e
        if r.status_code == 401:
            raise PluginError("OPNsense rejected the API key or secret")
        if r.status_code == 403:
            raise Forbidden(path)
        if r.status_code == 404:
            raise NotFound(path)
        if r.status_code >= 400:
            raise PluginError(f"OPNsense answered {r.status_code} for {path}")
        try:
            return r.json()
        except json.JSONDecodeError as e:
            raise PluginError(
                f"{self.base} did not answer with JSON: is it the OPNsense address?"
            ) from e

    def stream_second_event(self, path: str, timeout: float = 4) -> dict[str, Any] | None:
        """Reads a server-sent events stream until its second event. The first
        event of OPNsense's CPU stream is the average since boot."""
        events = 0
        try:
            with self.http.stream("GET", path, timeout=timeout) as r:
                if r.status_code == 403:
                    raise Forbidden(path)
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
