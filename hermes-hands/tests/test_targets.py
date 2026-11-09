import sys
import types

import pytest

from hands import targets


@pytest.fixture
def session(monkeypatch):
    """The tool call's session context: ``session(platform=..., user_id=...)``."""
    values = {}
    module = types.ModuleType("gateway.session_context")
    module.get_session_env = lambda name, default="": values.get(name, default)
    package = types.ModuleType("gateway")
    package.__path__ = []
    monkeypatch.setitem(sys.modules, "gateway", package)
    monkeypatch.setitem(sys.modules, "gateway.session_context", module)

    def bind(*, platform="", user_id=""):
        values.update(HERMES_SESSION_PLATFORM=platform, HERMES_SESSION_USER_ID=user_id)

    return bind


def resolve(default_target="server", session_key="chat", in_cron=False):
    return targets.resolve_target(
        session_key=session_key, in_cron=in_cron, default_target=default_target
    )


def test_caller_ids():
    assert targets.caller_id("desktop", "") == targets.caller_id("cli", "x") == targets.LOCAL
    assert targets.caller_id("Telegram", "42") == "telegram:42"
    assert targets.caller_id("telegram", "") == ""  # a chat sender with no id is nobody


def test_a_device_applies_only_to_the_person_who_chose_it(session, monkeypatch):
    """R13, R14, R34: whoever shares the session (a group, a thread, a Slack group DM) and is not
    the one who sent /hands use gets the server."""
    monkeypatch.setattr(targets.store, "get_session_target", lambda key: ("laptop", "slack:U1"))
    session(platform="slack", user_id="U1")
    assert resolve() == "laptop"
    session(platform="slack", user_id="U2")
    assert resolve() == "server"
    session(platform="slack", user_id="")
    assert resolve() == "server"
    assert resolve(in_cron=True) == "server"
    monkeypatch.setattr(targets.store, "get_session_target", lambda key: ("laptop", ""))
    session(platform="slack", user_id="U1")
    assert resolve() == "server"  # a target stored before owners were recorded


def test_server_targets_apply_to_everyone(session, monkeypatch):
    monkeypatch.setattr(targets.store, "get_session_target", lambda key: ("server", "slack:U1"))
    session(platform="slack", user_id="U2")
    assert resolve(default_target="laptop") == "server"


def test_a_device_default_target_applies_only_at_the_gateway_host(session, monkeypatch):
    monkeypatch.setattr(targets.store, "get_session_target", lambda key: None)
    session(platform="desktop")
    assert resolve(default_target="laptop") == "laptop"
    assert resolve(default_target="laptop", session_key="") == "laptop"
    session(platform="telegram", user_id="42")
    assert resolve(default_target="laptop") == "server"
    assert resolve(default_target="laptop", in_cron=True) == "server"
