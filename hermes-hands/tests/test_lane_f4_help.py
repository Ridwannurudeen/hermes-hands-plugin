from types import SimpleNamespace

import pytest

pytest.importorskip("hermes_cli.plugins")

from hermes_cli.plugins import PluginContext, PluginManager  # noqa: E402
from hermes_cli.plugins_manifest import PluginManifest  # noqa: E402

from hands import protocol  # noqa: E402
from hands_fakes import Device, hands_db, load_plugin_api, make_app  # noqa: E402,F401
from test_plugin_api import plugin  # noqa: E402,F401


@pytest.fixture
def help_plugin(plugin, tmp_path):
    ctx, hands, provider = plugin
    manager = PluginManager(scope_key=str(tmp_path))
    real_ctx = PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager)
    ctx._gateway_injection_allowed = real_ctx._gateway_injection_allowed
    ctx._manager = manager
    ctx.inject_message = real_ctx.inject_message
    device = Device()
    hands.store.record_seen(
        device.device_id, instance="serve-1", witness=True, session_state="active",
        capabilities=["witness-v1", "help-v1"],
    )
    origin = {"platform": "telegram", "chat_id": "chat-1", "chat_type": "dm", "user_id": "42"}
    hands.store.set_help_origin(device.device_id, "telegram:42", origin, "session-1")
    return SimpleNamespace(
        ctx=ctx, hands=hands, provider=provider, manager=manager, device=device, origin=origin,
        api=make_app(load_plugin_api()), config=tmp_path / "config.yaml",
    )


def _send(rig, request_id="a" * 32):
    _, headers, path, raw = rig.device.request("/device/help", {
        "request_id": request_id, "instance": "serve-1", "text": "Please help",
    })
    response = rig.api.post(path, content=raw, headers=headers)
    nonce = protocol.parse_bearer(headers["authorization"].split(" ", 1)[1]).nonce
    assert response.headers["X-Hands-Nonce"] == nonce
    assert protocol.verify_request(
        rig.provider.keys.relay_public, response.headers["X-Hands-Signature"], protocol.R2D,
        int(response.headers["X-Hands-Ts"]), nonce, "POST", path, response.content,
    )
    return response


@pytest.mark.parametrize("injector", [False, True])
@pytest.mark.parametrize("entry", [
    "{}", "{allow_gateway_injection: false}", "{allow_gateway_injection: 'true'}",
    "{settings: {allow_gateway_injection: true}}",
])
def test_disabled_help_is_signed_and_never_stored(help_plugin, entry, injector):
    rig = help_plugin
    rig.config.write_text(f"plugins:\n  entries:\n    hermes-hands: {entry}\n", encoding="utf-8")
    if injector:
        rig.manager.set_gateway_message_injector(object(), lambda **kwargs: True)
    response = _send(rig)
    assert response.status_code == 409
    assert response.json()["error"] == "help_disabled"
    assert rig.hands.store.get_help_request(rig.device.device_id, "a" * 32) is None


def test_enabled_dashboard_help_stays_pending_until_gateway_can_deliver(help_plugin):
    rig = help_plugin
    rig.config.write_text(
        "plugins:\n  entries:\n    hermes-hands:\n      allow_gateway_injection: true\n",
        encoding="utf-8",
    )
    assert rig.manager.has_gateway_message_injector is False
    response = _send(rig)
    assert response.status_code == 200
    assert response.json() == {"request_id": "a" * 32, "status": "accepted"}
    pending = rig.hands.store.get_help_request(rig.device.device_id, "a" * 32)
    assert pending["status"] == "pending" and pending["attempts"] == 0

    class OneTick:
        def __init__(self):
            self.waits = 0

        def wait(self, _timeout):
            self.waits += 1
            return self.waits == 2

    rig.hands.client._help_poller(rig.ctx, OneTick())
    assert rig.hands.store.get_help_request(rig.device.device_id, "a" * 32)["attempts"] == 0
    gateway_manager = PluginManager(scope_key=rig.manager.scope_key)
    gateway_ctx = PluginContext(PluginManifest(name="hermes-hands", kind="backend"), gateway_manager)
    delivered = []
    gateway_manager.set_gateway_message_injector(
        object(), lambda **kwargs: delivered.append(kwargs) or True,
    )
    rig.hands.client._help_poller(gateway_ctx, OneTick())
    queued = rig.hands.store.get_help_request(rig.device.device_id, "a" * 32)
    assert queued["status"] == "queued" and queued["attempts"] == 1
    assert len(delivered) == 1 and delivered[0]["origin"] == rig.origin
    assert rig.manager.has_gateway_message_injector is False


def test_unconfigured_help_is_signed_and_never_stored(help_plugin, monkeypatch):
    rig = help_plugin
    monkeypatch.setattr(rig.hands.relay, "_help_context", None)
    response = _send(rig)
    assert response.status_code == 409 and response.json()["error"] == "help_disabled"
    assert rig.hands.store.get_help_request(rig.device.device_id, "a" * 32) is None
