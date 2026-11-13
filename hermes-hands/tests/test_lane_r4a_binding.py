import contextvars
import threading

import pytest

from hands import client, store
from hands_fakes import Device, hands_db  # noqa: F401


@pytest.fixture(autouse=True)
def fresh_bindings(monkeypatch):
    monkeypatch.setattr(
        client, "_TOOL_SESSION", contextvars.ContextVar("r4a_b_tool_session", default=None)
    )
    monkeypatch.setattr(
        client, "_CALL_CELL", contextvars.ContextVar("r4a_b_call_cell", default=None)
    )
    monkeypatch.setattr(client, "_RUNNING_CALLS", {})
    monkeypatch.setattr(client, "_RUNNING_COUNTS", {}, raising=False)
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})


def _decision(device_id):
    return {"decision": {"device_id": device_id, "state": [False, "normal", None]}}


def test_two_running_calls_with_one_id_carry_no_decision_and_leave_no_binding(hands_db):
    """r3-binding-3: a second call under the same (session_id, tool_call_id) must not let either
    hook's decision reach the other call, and nothing may stay behind for a later call."""
    first, second = Device("first"), Device("second")
    started, release = threading.Event(), threading.Event()
    seen = {}

    def first_body(_args):
        client.bind_tool_session(
            store.device_by_id(first.device_id), session_id="s1", tool_call_id="dup"
        )
        started.set()
        release.wait(5)
        seen["first"] = client._decision_fields()

    thread = threading.Thread(
        target=client.tool_execution,
        kwargs={"args": {}, "next_call": first_body, "session_id": "s1", "tool_call_id": "dup"},
    )
    thread.start()
    assert started.wait(5)

    def second_body(_args):
        client.bind_tool_session(
            store.device_by_id(second.device_id), session_id="s1", tool_call_id="dup"
        )
        return client._decision_fields()

    seen["second"] = client.tool_execution(
        args={}, next_call=second_body, session_id="s1", tool_call_id="dup"
    )
    client.bind_tool_session(
        store.device_by_id(second.device_id), session_id="s1", tool_call_id="dup"
    )
    release.set()
    thread.join(5)
    assert seen == {"first": {}, "second": {}}
    assert client._RUNNING_CALLS == {} and client._CALL_SESSIONS == {}


def test_a_call_without_an_id_never_reads_an_enclosing_calls_decision(hands_db):
    """r3-binding-2: an id-less inner call has no key a hook can name. It keeps its caller's own
    binding, set by a hook that ran in this context, and never the enclosing call's cell."""
    outer, inner = Device("outer"), Device("inner")

    def outer_body(_args):
        client.bind_tool_session(
            store.device_by_id(outer.device_id), session_id="s1", tool_call_id="c1"
        )

        def inner_body(_args):
            client.bind_tool_session(store.device_by_id(inner.device_id), session_id="s1")
            return client._decision_fields()

        return client._decision_fields(), client.tool_execution(
            args={}, next_call=inner_body, session_id="s1", tool_call_id=""
        )

    outer_seen, inner_seen = client.tool_execution(
        args={}, next_call=outer_body, session_id="s1", tool_call_id="c1"
    )
    assert outer_seen == _decision(outer.device_id)
    assert inner_seen == _decision(inner.device_id)


def test_an_id_less_call_with_no_binding_in_its_context_sends_no_decision(hands_db, monkeypatch):
    # The session's one running call is the outer one; an id-less call must not adopt it.
    monkeypatch.setenv("HERMES_SESSION_ID", "s1")
    outer = Device("outer")

    def outer_body(_args):
        client.bind_tool_session(
            store.device_by_id(outer.device_id), session_id="s1", tool_call_id="c1"
        )
        return client.tool_execution(
            args={},
            next_call=lambda _args: client._decision_fields(),
            session_id="s1",
            tool_call_id="",
        )

    assert (
        client.tool_execution(args={}, next_call=outer_body, session_id="s1", tool_call_id="c1")
        == {}
    )


def test_a_body_without_its_call_cell_finds_only_its_sessions_one_running_call(hands_db, monkeypatch):
    """r3-binding-1: a body that lost _CALL_CELL finds its call by the session id while that call is
    the session's only running one. Another session, no session id or a second running call of the
    session finds nothing."""
    pytest.importorskip("gateway.session_context")
    device = Device()
    reads = {}

    def read(session_id):
        monkeypatch.setenv("HERMES_SESSION_ID", session_id)
        return contextvars.Context().run(client._decision_fields)

    def body(_args):
        client.bind_tool_session(
            store.device_by_id(device.device_id), session_id="s1", tool_call_id="c1"
        )
        reads["own"] = read("s1")
        reads["other_session"] = read("s2")
        reads["no_session"] = read("")
        reads["second_call"] = client.tool_execution(
            args={}, next_call=lambda _args: read("s1"), session_id="s1", tool_call_id="c2"
        )

    client.tool_execution(args={}, next_call=body, session_id="s1", tool_call_id="c1")
    assert reads == {
        "own": _decision(device.device_id),
        "other_session": {},
        "no_session": {},
        "second_call": {},
    }
    assert read("s1") == {}  # the call has finished


@pytest.mark.parametrize("foreign_id", ["another-call", ""])
def test_a_lost_context_cannot_adopt_a_witness_call_with_different_shown_arguments(hands_db, monkeypatch, foreign_id):
    monkeypatch.setenv("HERMES_SESSION_ID", "s1")
    monkeypatch.setenv("HERMES_TOOL_CALL_ID", foreign_id)
    device = Device()
    store.record_seen(device.device_id, witness=True, session_state="active", instance="serve-1", capabilities=["witness-v1"])
    shown = ("terminal", {"command": "echo approved"})

    def body(_args):
        client.bind_tool_session(store.device_by_id(device.device_id), session_id="s1", tool_call_id="own-call")
        client.record_shown("s1", "own-call", *shown, "hands-witness:own")
        client.record_approval("s1", "own-call", "hands-witness:own")
        lost = contextvars.Context()
        with pytest.raises(client.HandsError, match="not the one the helper approved"):
            lost.run(client.shown_call, lambda candidate: candidate == ("terminal", {"command": "echo foreign"}))
        assert client._CLAIMED_CALLS == set()
        assert lost.run(client.shown_call, lambda candidate: candidate == shown) == shown
        assert lost.run(client._decision_fields)["decision"]["device_id"] == device.device_id

    client.tool_execution(args=shown[1], next_call=body, tool_name="terminal", session_id="s1", tool_call_id="own-call")
    assert client._RUNNING_CALLS == {} and client._CLAIMED_CALLS == set()
