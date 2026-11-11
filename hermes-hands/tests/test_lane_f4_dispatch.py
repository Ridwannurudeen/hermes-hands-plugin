import contextvars
from functools import partial
from types import SimpleNamespace

import pytest

from hands import client, store
from hands_fakes import Device, hands_db, wired  # noqa: F401


@pytest.fixture
def dispatch(hands_db, monkeypatch):
    plugins = pytest.importorskip("hermes_cli.plugins")
    from hermes_cli.middleware import run_tool_execution_middleware

    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("f4_dispatch", default=None))
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})
    manager = plugins.PluginManager(scope_key=str(hands_db))
    manager._middleware["tool_execution"] = [client.tool_execution]
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)
    return manager, run_tool_execution_middleware


def _dispatch_binding(manager, snapshot, session_id, tool_call_id):
    def hook(**kwargs):
        client.bind_tool_session(
            snapshot, session_id=kwargs["session_id"], tool_call_id=kwargs["tool_call_id"]
        )
        return {"action": "approve"}

    result = manager._run_hook_callback_bounded("pre_tool_call", hook, {
        "tool_name": "terminal", "args": {"command": "hostname"},
        "session_id": session_id, "tool_call_id": tool_call_id,
    }, 2)
    assert result == {"action": "approve"}


def test_hook_decision_survives_real_bounded_dispatch(hands_db, monkeypatch):
    plugins = pytest.importorskip("hermes_cli.plugins")
    from hermes_cli.middleware import run_tool_execution_middleware

    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("f4_dispatch", default=None))
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})
    device = Device()
    snapshot = store.device_by_id(device.device_id)
    manager = plugins.PluginManager(scope_key=str(hands_db))
    manager._middleware["tool_execution"] = [client.tool_execution]
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)

    def hook(**kwargs):
        client.bind_tool_session(snapshot, session_id=kwargs["session_id"], tool_call_id=kwargs["tool_call_id"])
        return {"action": "approve"}

    decision = manager._run_hook_callback_bounded("pre_tool_call", hook, {
        "tool_name": "terminal", "args": {"command": "hostname"},
        "session_id": "session-1", "tool_call_id": "call-1",
    }, 2)
    assert decision["action"] == "approve"
    assert client._decision_fields() == {}
    observed = run_tool_execution_middleware("terminal", {}, lambda args: client._decision_fields(),
                                             session_id="session-1", tool_call_id="call-1")
    assert observed == {
        "decision": {"device_id": device.device_id, "state": [False, "normal", None]},
    }
    assert client._decision_fields() == {}
    assert client._CALL_SESSIONS == {}


def test_interleaved_dispatch_keys_do_not_exchange_decisions(dispatch):
    manager, execute = dispatch
    first, second = Device("first"), Device("second")
    keys = [("s1", "call"), ("s2", "call"), ("s1", "other")]
    devices = [first, second, second]
    for (session_id, tool_call_id), device in zip(keys, devices):
        _dispatch_binding(manager, store.device_by_id(device.device_id), session_id, tool_call_id)
    assert client._decision_fields() == {}
    for index in (1, 2, 0):
        session_id, tool_call_id = keys[index]
        observed = execute("terminal", {}, lambda _args: client._decision_fields(),
                           session_id=session_id, tool_call_id=tool_call_id)
        assert observed == {
            "decision": {"device_id": devices[index].device_id, "state": [False, "normal", None]},
        }
        assert client._decision_fields() == {}
    assert client._CALL_SESSIONS == {}


def test_dispatch_binding_is_consumed_once_and_cache_miss_refuses_witness(dispatch, wired):
    manager, execute = dispatch
    hub, _ = wired
    device = Device()
    store.record_seen(device.device_id, witness=True, session_state="active", instance="w1")
    snapshot = store.device_by_id(device.device_id)
    _dispatch_binding(manager, snapshot, "s1", "call")
    observed = execute("terminal", {}, lambda _args: client._decision_fields(),
                       session_id="s1", tool_call_id="call")
    assert observed["decision"]["state"] == [True, "active", "w1"]
    client.bind_tool_session(snapshot)
    caller = client._decision_fields()
    attempts = []

    def start(_args):
        attempts.append(client._decision_fields())
        return client.start_job("laptop", script="hostname", login=False, timeout=5)

    with pytest.raises(client.HandsError, match="session changed after the tool decision"):
        execute("terminal", {}, start, session_id="s1", tool_call_id="call")
    assert attempts == [{}]
    assert client._decision_fields() == caller
    assert client._CALL_SESSIONS == {}
    assert not hub._jobs


def test_downstream_exception_restores_caller_binding_without_retry(dispatch):
    manager, execute = dispatch
    first, second = Device("first"), Device("second")
    client.bind_tool_session(store.device_by_id(first.device_id))
    caller = client._decision_fields()
    _dispatch_binding(manager, store.device_by_id(second.device_id), "s1", "call")
    failure = RuntimeError("downstream failed")
    attempts = []

    def fail(_args):
        attempts.append(client._decision_fields())
        raise failure

    with pytest.raises(RuntimeError) as raised:
        execute("terminal", {}, fail, session_id="s1", tool_call_id="call")
    assert raised.value is failure
    assert len(attempts) == 1
    assert attempts[0]["decision"]["device_id"] == second.device_id
    assert client._decision_fields() == caller
    assert client._CALL_SESSIONS == {}


def test_cache_evicts_oldest_without_changing_active_execution_context(dispatch):
    manager, execute = dispatch
    first, second = Device("first"), Device("second")
    first_snapshot = store.device_by_id(first.device_id)
    second_snapshot = store.device_by_id(second.device_id)
    _dispatch_binding(manager, first_snapshot, "active", "call")
    _dispatch_binding(manager, first_snapshot, "oldest", "call")

    def fill_cache(_args):
        before = client._decision_fields()

        def hook(**kwargs):
            for index in range(4096):
                client.bind_tool_session(second_snapshot, session_id="new", tool_call_id=str(index))
            return {"action": "approve"}

        assert manager._run_hook_callback_bounded("pre_tool_call", hook, {}, 2) == {"action": "approve"}
        assert len(client._CALL_SESSIONS) == 4096
        assert ("oldest", "call") not in client._CALL_SESSIONS
        assert ("new", "0") in client._CALL_SESSIONS
        assert client._decision_fields() == before
        return before

    observed = execute("terminal", {}, fill_cache, session_id="active", tool_call_id="call")
    assert observed["decision"]["device_id"] == first.device_id
    assert client._decision_fields() == {}
    assert execute("terminal", {}, lambda _args: client._decision_fields(),
                   session_id="oldest", tool_call_id="call") == {}
    last = execute("terminal", {}, lambda _args: client._decision_fields(),
                   session_id="new", tool_call_id="4095")
    assert last["decision"]["device_id"] == second.device_id


@pytest.mark.parametrize("active", [False, True], ids=["normal", "active_witness"])
def test_actual_witness_hook_hands_snapshot_to_real_dispatch_middleware(dispatch, monkeypatch, active):
    from gateway.session_context import scoped_session_key
    from hands import environment, witness

    manager, execute = dispatch
    device = Device()
    store.record_seen(
        device.device_id, instance="serve-1", witness=active,
        session_state="active" if active else "normal",
        capabilities=["witness-v1"] if active else [],
    )
    monkeypatch.setattr(environment, "resolve_current_target", lambda _ctx: "laptop")
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    monkeypatch.setattr(witness, "_other_hooks", lambda _ctx: False)
    ctx = SimpleNamespace(current_cron_execution=lambda: None)
    with scoped_session_key("route-1"):
        decision = manager._run_hook_callback_bounded(
            "pre_tool_call", partial(witness.pre_tool_call, ctx), {
                "tool_name": "terminal", "args": {"command": "echo check"},
                "session_id": "agent-1", "tool_call_id": "actual-hook-call",
            }, 2,
        )
    if active:
        assert decision["action"] == "approve"
    else:
        assert decision is None
    observed = execute("terminal", {}, lambda _args: client._decision_fields(),
                       session_id="agent-1", tool_call_id="actual-hook-call")
    assert observed == {
        "decision": {
            "device_id": device.device_id,
            "state": [active, "active" if active else "normal", "serve-1" if active else None],
        },
    }
    assert client._decision_fields() == {}
    assert client._CALL_SESSIONS == {}
