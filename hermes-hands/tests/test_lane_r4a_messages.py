import json
import logging
import sqlite3
import sys
import types

import pytest

from hands import client, messages, store


@pytest.mark.parametrize(
    ("error", "sentence"),
    [
        (
            "device_error",
            "The device ended the session because of an error. Nothing more will run.",
        ),
        ("device_is_stopping", "The person is ending the session. Nothing more will run."),
        ("device is stopping", "The person is ending the session. Nothing more will run."),
        (
            "session_ended",
            "The session on laptop ended. Nothing else will run. Do not guess a reason or retry.",
        ),
    ],
)
def test_session_end_codes_read_as_plain_sentences(error, sentence):
    """r3-packaging-4 and the R4B contract: no internal code reaches the helper."""
    assert messages.device_result_error(error, "laptop") == sentence



def _handlers(monkeypatch, tmp_path):
    import importlib

    monkeypatch.delitem(sys.modules, "hands.tools", raising=False)
    tools = importlib.import_module("hands.tools")
    constants = types.ModuleType("hermes_constants")
    constants.get_hermes_home = lambda: tmp_path
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    gateway = types.ModuleType("gateway")
    gateway.__path__ = []
    session_context = types.ModuleType("gateway.session_context")
    session_context.get_session_env = lambda key, default="": "session"
    monkeypatch.setitem(sys.modules, "gateway", gateway)
    monkeypatch.setitem(sys.modules, "gateway.session_context", session_context)
    monkeypatch.setattr(store, "get_session_target", lambda key: ("laptop", "session:session"))
    monkeypatch.setattr(store, "get_device", lambda name: {"name": name})
    handlers = {}
    ctx = types.SimpleNamespace(
        current_cron_execution=lambda: None,
        get_config=lambda key, default=None: default,
        register_tool=lambda *, name, handler, **kwargs: handlers.__setitem__(name, handler),
    )
    tools.register_tools(ctx)
    return handlers


def _raise(exc):
    def fail(*args, **kwargs):
        raise exc

    return fail


def test_a_gateway_failure_never_hands_python_text_to_the_model(monkeypatch, tmp_path, caplog):
    """r3-packaging-5: an OSError, sqlite error or KeyError carries paths and internals."""
    handlers = _handlers(monkeypatch, tmp_path)
    secret = f"[Errno 28] No space left on device: '{tmp_path}/cache/x.png'"
    monkeypatch.setattr(client, "request_screenshot", lambda device: b"png")
    monkeypatch.setattr(type(tmp_path), "write_bytes", _raise(OSError(secret)))
    monkeypatch.setattr(
        store, "list_devices", _raise(sqlite3.OperationalError("disk I/O error at /x"))
    )
    monkeypatch.setattr(client, "request_checkup", _raise(KeyError("checkup")))
    with caplog.at_level(logging.WARNING):
        results = {
            name: json.loads(handlers[name]({}))
            for name in ("hands_screenshot", "hands_devices", "hands_checkup")
        }
    assert results == {
        "hands_screenshot": {"error": messages.SCREENSHOT_GATEWAY_FAILED},
        "hands_devices": {"error": messages.DEVICES_GATEWAY_FAILED},
        "hands_checkup": {"error": messages.CHECKUP_GATEWAY_FAILED},
    }
    assert "No space left" in caplog.text


def test_a_hands_refusal_still_reaches_the_model_as_its_own_sentence(monkeypatch, tmp_path):
    handlers = _handlers(monkeypatch, tmp_path)
    offline = "hands: laptop is offline, so nothing ran."
    monkeypatch.setattr(client, "request_screenshot", _raise(client.HandsError(offline)))
    monkeypatch.setattr(
        client, "request_checkup", _raise(client.RelayUnavailable(messages.RELAY_DOWN))
    )
    assert json.loads(handlers["hands_screenshot"]({})) == {"error": offline}
    assert json.loads(handlers["hands_checkup"]({})) == {"error": messages.RELAY_DOWN}


def test_a_device_without_a_screen_reads_as_a_plain_sentence():
    text = messages.device_result_error("screenshot_unavailable", "laptop")
    assert "screenshot_unavailable" not in text
    assert "laptop has no screen" in text and "Nothing was captured" in text
