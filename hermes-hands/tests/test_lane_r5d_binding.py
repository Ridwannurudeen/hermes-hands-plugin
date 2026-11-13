import contextvars
import threading

import pytest

from hands import client


@pytest.fixture(autouse=True)
def fresh_bindings(monkeypatch):
    monkeypatch.setattr(
        client, "_TOOL_SESSION", contextvars.ContextVar("r5d_tool_session", default=None)
    )
    monkeypatch.setattr(client, "_CALL_CELL", contextvars.ContextVar("r5d_call_cell", default=None))
    monkeypatch.setattr(client, "_RUNNING_CALLS", {})
    monkeypatch.setattr(client, "_RUNNING_COUNTS", {})
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})
    monkeypatch.setattr(client, "_APPROVED_CALLS", {})


NORMAL = {"device_id": "d1", "witness": False, "session_state": "normal", "instance": None}
WITNESS = {"device_id": "d1", "witness": True, "session_state": "active", "instance": "serve-2"}


def _fields(device):
    return {
        "decision": {
            "device_id": device["device_id"],
            "state": [device["witness"], device["session_state"], device["instance"]],
        }
    }


def test_a_context_copied_in_the_body_keeps_the_decision_after_the_call_ends():
    """Core's process registry polls a background job from a context copied inside the tool body
    (process_registry.py _track_started), after the call has returned."""
    copies = []

    def body(_args):
        client.bind_tool_session(WITNESS, session_id="s1", tool_call_id="c1")
        client.record_shown("s1", "c1", "terminal", {}, "hands-witness:r5d")
        client.record_approval("s1", "c1", "hands-witness:r5d")
        copies.append(contextvars.copy_context())

    client.tool_execution(args={}, next_call=body, session_id="s1", tool_call_id="c1")

    assert client._RUNNING_CALLS == {} and client._CALL_SESSIONS == {}
    assert copies[0].run(client._decision_fields) == _fields(WITNESS)
    assert client._decision_fields() == {}


def test_a_hook_only_bind_under_a_running_calls_key_leaves_that_call_no_decision():
    """r4-batch-2: a pre_tool_call hook for another dispatch with the same ids, whose own call never
    runs, must not move the running call to a later device session."""
    started, release, seen = threading.Event(), threading.Event(), {}

    def body(_args):
        client.bind_tool_session(NORMAL, session_id="s1", tool_call_id="K")
        seen["before"] = client._decision_fields()
        started.set()
        release.wait(5)
        seen["after"] = client._decision_fields()

    thread = threading.Thread(
        target=client.tool_execution,
        kwargs={"args": {}, "next_call": body, "session_id": "s1", "tool_call_id": "K"},
    )
    thread.start()
    assert started.wait(5)
    hook = threading.Thread(
        target=client.bind_tool_session,
        args=(WITNESS,),
        kwargs={"session_id": "s1", "tool_call_id": "K"},
    )
    hook.start()
    hook.join(5)
    release.set()
    thread.join(5)

    assert seen == {"before": _fields(NORMAL), "after": {}}
    assert client._RUNNING_CALLS == {} and client._CALL_SESSIONS == {}


@pytest.mark.parametrize("device", [NORMAL, None], ids=["device", "server"])
def test_the_same_decision_bound_again_keeps_the_call_decision(device):
    def body(_args):
        client.bind_tool_session(device, session_id="s1", tool_call_id="K")
        client.bind_tool_session(device, session_id="s1", tool_call_id="K")
        return client._decision_fields()

    seen = client.tool_execution(args={}, next_call=body, session_id="s1", tool_call_id="K")

    assert seen == ({} if device is None else _fields(NORMAL))


def test_a_server_decision_then_a_device_decision_under_one_key_carries_none():
    """None is a real decision (the gateway target), so a later device bind must not replace it."""

    def body(_args):
        client.bind_tool_session(None, session_id="s1", tool_call_id="K")
        client.bind_tool_session(WITNESS, session_id="s1", tool_call_id="K")
        return client._decision_fields()

    assert client.tool_execution(args={}, next_call=body, session_id="s1", tool_call_id="K") == {}


def test_a_decision_bound_before_the_call_starts_is_kept_when_the_hook_binds_it_again():
    client.bind_tool_session(NORMAL, session_id="s1", tool_call_id="K")

    def body(_args):
        client.bind_tool_session(NORMAL, session_id="s1", tool_call_id="K")
        return client._decision_fields()

    assert client.tool_execution(
        args={}, next_call=body, session_id="s1", tool_call_id="K"
    ) == _fields(NORMAL)
