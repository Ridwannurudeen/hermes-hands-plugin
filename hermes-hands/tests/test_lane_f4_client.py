import contextvars
import threading

import pytest

from hands import client, store
from hands.handle import RemoteProcessHandle
from hands_fakes import Device, hands_db, wired  # noqa: F401


@pytest.fixture(autouse=True)
def isolated_tool_session(monkeypatch):
    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("f4_tool_session", default=None))


@pytest.mark.parametrize("witness", [False, True])
def test_tool_decision_freezes_mutable_device_snapshot(hands_db, witness):
    device = Device()
    store.record_seen(
        device.device_id, instance="first", witness=witness,
        session_state="active" if witness else "normal",
    )
    snapshot = store.device_by_id(device.device_id)
    expected = {
        "decision": {
            "device_id": device.device_id,
            "state": [witness, "active" if witness else "normal", "first" if witness else None],
        }
    }

    def body(_args):
        client.bind_tool_session(snapshot, session_id="s1", tool_call_id="c1")
        client.record_shown("s1", "c1", "terminal", {}, "hands-witness:f4")
        client.record_approval("s1", "c1", "hands-witness:f4")
        snapshot.update(device_id="changed", witness=not witness, session_state="stopped", instance="other")
        store.record_seen(device.device_id, instance="second", witness=True, session_state="active")
        assert client._decision_fields() == expected
        exposed = client._decision_fields()
        exposed["decision"]["state"][0] = not witness
        assert client._decision_fields() == expected

    client.tool_execution(args={}, next_call=body, session_id="s1", tool_call_id="c1")


@pytest.mark.parametrize("kind", ["exec", "screenshot", "checkup"])
def test_every_device_request_carries_the_original_decision(wired, monkeypatch, kind):
    hub, _ = wired
    device = Device()
    client.bind_tool_session(store.device_by_id(device.device_id))
    expected = {"device_id": device.device_id, "state": [False, "normal", None]}
    store.record_seen(device.device_id, instance="new", witness=True, session_state="active")
    sent = []
    original = client._http.post

    def post(path, **kwargs):
        sent.append((path, kwargs["json"]))
        return original(path, **kwargs)

    monkeypatch.setattr(client._http, "post", post)
    with pytest.raises(client.HandsError, match="session changed after the tool decision"):
        if kind == "exec":
            client.start_job("laptop", script="true", login=False, timeout=5)
        elif kind == "screenshot":
            client.request_screenshot("laptop")
        else:
            client.request_checkup("laptop")
    assert len(sent) == 1
    assert sent[0][0] == "/local/exec"
    assert sent[0][1]["type"] == kind
    assert sent[0][1]["decision"] == expected
    assert not hub._jobs


def test_remote_worker_keeps_copied_decision_after_parent_context_clears(hands_db, monkeypatch):
    device = Device()
    client.bind_tool_session(store.device_by_id(device.device_id))
    reached = threading.Event()
    release = threading.Event()
    sent = []
    start = client.start_job

    def delayed_start(*args, **kwargs):
        reached.set()
        assert release.wait(5)
        return start(*args, **kwargs)

    def post(route, body, **kwargs):
        sent.append((route, body))
        return {"job_id": "job-1"}

    monkeypatch.setattr(client, "start_job", delayed_start)
    monkeypatch.setattr(client, "_post", post)
    monkeypatch.setattr(client, "job_output", lambda *_args: {
        "chunks": [], "next": 0, "done": True, "returncode": 0,
    })
    proc = RemoteProcessHandle("laptop", "true", login=False, timeout=5)
    try:
        assert reached.wait(5)
        client.bind_tool_session(None)
        assert client._decision_fields() == {}
    finally:
        release.set()
    assert proc.wait(5) == 0
    assert proc.stdout.read() == ""
    proc.stdout.close()
    assert sent[0][0] == "/local/exec"
    assert sent[0][1]["decision"] == {
        "device_id": device.device_id, "state": [False, "normal", None],
    }


def test_server_clear_and_independent_contexts_do_not_bleed(hands_db):
    first, second = Device("first"), Device("second")
    first_context, second_context = contextvars.Context(), contextvars.Context()
    first_context.run(client.bind_tool_session, store.device_by_id(first.device_id))
    second_context.run(client.bind_tool_session, store.device_by_id(second.device_id))
    assert client._decision_fields() == {}
    assert first_context.run(client._decision_fields)["decision"]["device_id"] == first.device_id
    assert second_context.run(client._decision_fields)["decision"]["device_id"] == second.device_id
    first_context.run(client.bind_tool_session, None)
    assert first_context.run(client._decision_fields) == {}
    assert second_context.run(client._decision_fields)["decision"]["device_id"] == second.device_id
