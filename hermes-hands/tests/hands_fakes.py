"""Test doubles for the gateway-half tests: a fake ``plugins.plugin_storage``, a signing device, a
Relay wired to ``client`` through an httpx MockTransport playing the dashboard token seam, and a fake
device agent thread."""

from __future__ import annotations

import asyncio
import base64
import functools
import importlib.util
import json
import sqlite3
import sys
import threading
import time
import types
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from hands import client, protocol, relay, store

SEED = "ab" * 32
PLUGIN_DIR = Path(__file__).resolve().parents[1]
_LOCAL_ROUTES = {
    "/local/exec": "local_exec",
    "/local/output": "local_output",
    "/local/cancel": "local_cancel",
    "/local/state": "local_state",
}


@pytest.fixture
def hands_db(tmp_path, monkeypatch):
    """``plugins.plugin_storage.plugin_db`` opening plain SQLite files under ``tmp_path``."""
    storage = types.ModuleType("plugins.plugin_storage")

    def plugin_db(name, filename="data.db"):
        assert name == "hermes-hands"
        return sqlite3.connect(tmp_path / filename, timeout=5, check_same_thread=False)

    storage.plugin_db = plugin_db
    monkeypatch.setitem(sys.modules, "plugins.plugin_storage", storage)
    monkeypatch.setattr(store, "OFFLINE_AFTER", 20)
    return tmp_path


@dataclass(frozen=True)
class Principal:
    """Shape of ``hermes_cli.dashboard_auth.TokenPrincipal``."""

    principal: str
    provider: str = relay.PROVIDER
    scopes: tuple[str, ...] = ()


LOCAL = Principal("local", scopes=(relay.SCOPE_LOCAL,))


class Device:
    """A paired device that signs its requests exactly as the device agent does."""

    def __init__(
        self,
        name: str = "laptop",
        policy_hash: str = "p0",
        home: str = "C:\\Users\\person",
        device_os: str = "Windows-11-10.0.26300-SP0",
    ):
        self.name = name
        self.policy_hash = policy_hash
        self.private, self.public = protocol.generate_keypair()
        code = store.mint_pairing_code(name)
        self.device_id = store.complete_pairing(
            code,
            name=name,
            public_key=protocol.b64u(self.public),
            os=device_os,
            home=home,
            policy_hash=policy_hash,
        )

    def request(self, route: str, body: dict, *, tamper: bool = False):
        """``(principal, headers, path, body)`` for a signed device request to ``route``."""
        path = relay.API + route
        raw = protocol.canonical_json(body)
        ts, nonce = int(time.time()), protocol.new_nonce()
        signature = protocol.sign_request(self.private, protocol.D2R, ts, nonce, "POST", path, raw)
        headers = {
            "authorization": "Bearer "
            + protocol.make_bearer(self.device_id, self.private, ts=ts, nonce=nonce),
            "x-hands-signature": signature,
        }
        if tamper:
            raw += b" "
        return Principal(self.device_id, scopes=(relay.SCOPE_DEVICE,)), headers, path, raw


@pytest.fixture
def wired(hands_db, monkeypatch):
    """A Relay reachable through ``client``; returns ``(hub, keys)``."""
    keys = relay.derive_keys(SEED)
    hub = relay.Relay(keys)

    def seam(request: httpx.Request) -> httpx.Response:
        token = request.headers["authorization"].split(" ", 1)[1]
        principal = LOCAL if token == keys.local_bearer else None
        handler = getattr(hub, _LOCAL_ROUTES[request.url.path.removeprefix(relay.API)])
        reply = asyncio.run(handler(principal, request.headers, request.url.path, request.content))
        return httpx.Response(reply.status, content=reply.body, headers=reply.headers)

    transport = httpx.MockTransport(seam)
    monkeypatch.setattr(
        client.httpx, "Client", functools.partial(httpx.Client, transport=transport)
    )
    client.configure("http://127.0.0.1:9119/", keys.local_bearer)
    yield hub, keys
    client.configure("http://127.0.0.1:9119", None)


class Agent:
    """Polls the relay like the device agent. ``run(job) -> (output, returncode)`` executes exec
    jobs; screenshots answer with ``png``. Use as a context manager so the thread is joined."""

    def __init__(self, hub, device, run, png=b"\x89PNG"):
        self.hub, self.device, self.run, self.png = hub, device, run, png
        self.jobs: list[dict] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(5)

    def _call(self, handler, route, payload):
        principal, headers, path, raw = self.device.request(route, payload)
        return asyncio.run(getattr(self.hub, handler)(principal, headers, path, raw, "10.0.0.2"))

    def _result(self, job_id, seq, chunk="", done=False, **extra):
        payload = {"job_id": job_id, "seq": seq, "chunk": chunk, "done": done}
        if done:
            payload["returncode"] = extra.pop("returncode", 0)
            payload["error"] = extra.pop("error", None)
        self._call("device_result", "/device/result", {**payload, "policy_hash": "p0", **extra})

    def _loop(self):
        while not self.stop.is_set():
            reply = self._call("device_poll", "/device/poll", {"wait": 1})
            if reply.status != 200:
                continue
            job = json.loads(reply.body)
            self.jobs.append(job)
            if job["type"] == "screenshot":
                png = base64.b64encode(self.png).decode()
                self._result(job["job_id"], 0, done=True, returncode=0, error=None, png_b64=png)
            elif job["type"] == "exec":
                output, returncode = self.run(job)
                self._result(job["job_id"], 0, output)
                self._result(job["job_id"], 1, done=True, returncode=returncode)


class RegisterCtx:
    """The parts of ``PluginContext`` that ``register()`` and the terminal backend use."""

    def __init__(self):
        self.config = {}
        self.calls = []
        self.gateway_injection = True  # plugins.entries.hermes-hands.allow_gateway_injection

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def _gateway_injection_allowed(self) -> bool:
        return self.gateway_injection

    def current_cron_execution(self):
        return None

    def register_terminal_environment_provider(self, provider):
        self.calls.append(("terminal", provider))

    def register_dashboard_auth_provider(self, provider):
        from hermes_cli.dashboard_auth import registry

        registry.register_global_provider(provider)  # what PluginContext does (plugins.py:737-778)
        self.calls.append(("auth", provider))

    def register_command(self, name, handler, **kwargs):
        self.calls.append(("command", name))

    def register_middleware(self, name, fn):
        self.calls.append(("middleware", name))

    def register_cli_command(self, name, *args, **kwargs):
        self.calls.append(("cli", name))

    def register_tool(self, *, name, **kwargs):
        self.calls.append(("tool", name))

    def register_skill(self, name, path, description="", frontmatter=None):
        self.calls.append(("skill", name))

    def inject_message(self, content, role="user", *, session_key=None, origin=None):
        return False


def load_plugin_package():
    """``hermes_plugins.hermes_hands`` exactly as plugins_loader.py:811-837 imports it."""
    sys.modules.setdefault("hermes_plugins", types.ModuleType("hermes_plugins")).__path__ = []
    name = "hermes_plugins.hermes_hands"
    for key in [k for k in sys.modules if k == name or k.startswith(name + ".")]:
        del sys.modules[key]
    spec = importlib.util.spec_from_file_location(
        name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_plugin_api():
    """The dashboard file on its own, as web_server_dashboard.py:1233-1246 imports it."""
    name = "hermes_dashboard_plugin_hermes-hands"
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "dashboard" / "plugin_api.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def make_app(plugin_api, *, gateway: bool = False, base_url: str = "http://testserver"):
    """A dashboard-shaped app: the real token-auth middleware in front of the plugin router."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from hermes_cli.dashboard_auth import token_auth

    app = FastAPI()
    app.middleware("http")(token_auth.token_auth_middleware)
    app.include_router(plugin_api.router, prefix=relay.API)
    if gateway:
        app.state.gateway_runner = object()
    return TestClient(app, base_url=base_url)
