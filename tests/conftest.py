import json
from functools import partial
from pathlib import Path

import httpx
import pytest

import omini_opnsense.collect as collect_module
from omini_opnsense.client import Client

FIXTURES = Path(__file__).parent / "fixtures"


class FakeOPNsense:
    """Answers like an OPNsense 25.7 firewall, from the JSON files in fixtures/."""

    def __init__(self):
        self.routes = {}
        self.forbidden = set()
        self.calls = []
        for f in FIXTURES.glob("*.json"):
            path = "/api/" + f.stem.replace("__", "/")
            self.routes[path] = json.loads(f.read_text())
        self.routes["/api/diagnostics/cpu_usage/stream"] = (
            'data: {"total":12,"idle":88}\n\n'  # since boot: ignored
            'data: {"total":3,"user":2,"nice":0,"sys":1,"intr":0,"idle":97}\n\n'
        )
        self.auth = ("key", "secret")

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        if request.headers.get("authorization") != httpx.BasicAuth(*self.auth)._auth_header:
            return httpx.Response(401)
        path = request.url.path
        if any(path.startswith(p) for p in self.forbidden):
            return httpx.Response(403)
        if path not in self.routes:
            return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
        body = self.routes[path]
        if isinstance(body, str):
            return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})
        return httpx.Response(200, json=body)


@pytest.fixture
def opnsense(monkeypatch):
    fake = FakeOPNsense()
    monkeypatch.setattr(
        collect_module, "Client", partial(Client, transport=httpx.MockTransport(fake.handler))
    )
    return fake


@pytest.fixture
def cfg():
    from omini_sdk import Config

    return Config({"url": "https://192.168.1.1", "api_key": "key", "api_secret": "secret"})
