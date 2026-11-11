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


def test_an_id_less_call_with_no_binding_in_its_context_sends_no_decision(hands_db):
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


def test_the_running_call_is_found_only_by_its_own_hermes_ids(hands_db):
    """r3-binding-1: a body that lost _CALL_CELL finds its call by the ids Hermes binds around it,
    and a different or empty id finds nothing."""
    pytest.importorskip("tools.approval_context")
    from tools.approval_context import (
        reset_current_observability_context,
        set_current_observability_context,
    )

    device = Device()
    reads = {}

    def body(_args):
        client.bind_tool_session(
            store.device_by_id(device.device_id), session_id="s1", tool_call_id="c1"
        )
        for name, ids in {
            "own": ("s1", "c1"),
            "other_call": ("s1", "c2"),
            "other_session": ("s2", "c1"),
            "no_id": ("s1", ""),
        }.items():

            def read(ids=ids):
                tokens = set_current_observability_context(session_id=ids[0], tool_call_id=ids[1])
                try:
                    return client._decision_fields()
                finally:
                    reset_current_observability_context(tokens)

            reads[name] = contextvars.Context().run(read)

    client.tool_execution(args={}, next_call=body, session_id="s1", tool_call_id="c1")
    assert reads == {
        "own": _decision(device.device_id),
        "other_call": {},
        "other_session": {},
        "no_id": {},
    }

    tokens = set_current_observability_context(session_id="s1", tool_call_id="c1")
    try:
        assert client._decision_fields() == {}  # the call has finished
    finally:
        reset_current_observability_context(tokens)
