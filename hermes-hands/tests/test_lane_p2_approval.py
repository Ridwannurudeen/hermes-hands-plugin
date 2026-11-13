import contextvars
import threading

import pytest

from hands import client, messages, witness

WITNESS = {"device_id": "d1", "witness": True, "session_state": "active", "instance": "serve-2"}
NORMAL = {"device_id": "d2", "witness": False, "session_state": "normal", "instance": None}
WITNESS_FIELDS = {"decision": {"device_id": "d1", "state": [True, "active", "serve-2"]}}
RULE_KEY = "hands-witness:0123"


@pytest.fixture(autouse=True)
def fresh_tool_session(monkeypatch):
    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("p2_tool_session", default=None))
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})
    monkeypatch.setattr(client, "_CALL_CELL", contextvars.ContextVar("p2_call_cell", default=None))
    monkeypatch.setattr(client, "_RUNNING_CALLS", {})
    monkeypatch.setattr(client, "_RUNNING_COUNTS", {})
    monkeypatch.setattr(client, "_APPROVED_CALLS", {})
    monkeypatch.setattr(client, "_CLAIMED_CALLS", set())


def _answer(choice="once", *, pattern_key=f"plugin_rule:{RULE_KEY}", **ids):
    witness.post_approval_response(choice=choice, pattern_key=pattern_key, **ids)


def _call(body, *, device=WITNESS, session_id="s1", tool_call_id="c1", shown=("terminal", {})):
    """One tool call through the middleware; the hook binds its decision inside, as the agent loop does."""

    def next_call(_args):
        client.bind_tool_session(device, session_id=session_id, tool_call_id=tool_call_id)
        client.record_shown(session_id, tool_call_id, *shown, RULE_KEY)
        return body()

    return client.tool_execution(args={}, next_call=next_call, session_id=session_id, tool_call_id=tool_call_id)


def _refused(body, message=messages.WITNESS_NOT_APPROVED, **kwargs):
    with pytest.raises(client.HandsError) as raised:
        _call(body, **kwargs)
    assert str(raised.value) == message


def test_a_witness_job_without_a_recorded_approval_is_refused():
    _refused(client._decision_fields)
    assert client._RUNNING_CALLS == {} and client._APPROVED_CALLS == {}


@pytest.mark.parametrize("choice", ["once", "session", "always"])
def test_a_persons_yes_lets_only_that_calls_jobs_run(choice):
    def body():
        _answer(choice, session_id="s1", tool_call_id="c1")
        return client._decision_fields()

    assert _call(body) == WITNESS_FIELDS
    # A later call, and a repeat of the same ids, each need their own answer.
    _refused(client._decision_fields, tool_call_id="c2")
    _refused(client._decision_fields)


@pytest.mark.parametrize("choice", ["deny", "timeout", "cancelled", "smart_approve", "notify_failed", ""])
def test_answers_other_than_a_persons_yes_are_refused(choice):
    def body():
        _answer(choice, session_id="s1", tool_call_id="c1")
        return client._decision_fields()

    _refused(body)


@pytest.mark.parametrize(
    "pattern_key",
    ["protected_instruction_file", "rm -rf", "plugin_rule:other:1", "", "plugin_rule:hands-witness:external", RULE_KEY],
)
def test_a_yes_to_another_approval_card_is_refused(pattern_key):
    def body():
        _answer("once", pattern_key=pattern_key, session_id="s1", tool_call_id="c1")
        return client._decision_fields()

    _refused(body)


def test_an_approval_with_no_tool_call_id_records_nothing():
    _answer("once", session_id="s1", tool_call_id="")
    assert client._APPROVED_CALLS == {}

    def body():
        _answer("once", session_id="s1", tool_call_id="")
        return client._decision_fields()

    _refused(body)
    # A call without an id keeps only its caller's binding, which no answer can reach.
    client.bind_tool_session(WITNESS)
    _answer("once", session_id="", tool_call_id="")
    with pytest.raises(client.HandsError, match="nobody answered"):
        client.tool_execution(args={}, next_call=lambda _args: client._decision_fields(), session_id="s1", tool_call_id="")


def test_a_missing_session_id_matches_a_call_with_an_empty_session_id():
    def body():
        _answer("once", tool_call_id="c1")  # core leaves session_id out when it is empty
        return client._decision_fields()

    assert _call(body, session_id="") == WITNESS_FIELDS
    _refused(lambda: (_answer("once", tool_call_id="c1"), client._decision_fields())[1], session_id="s1")


def test_an_approval_given_before_the_call_starts_is_carried_into_it_once():
    # model_tools.handle_function_call runs pre_tool_call, and so the approval, before the middleware.
    client.bind_tool_session(WITNESS, session_id="s1", tool_call_id="c1")
    client.record_shown("s1", "c1", "terminal", {}, RULE_KEY)
    _answer("once", pattern_key="plugin_rule:hands-witness:external", session_id="s1", tool_call_id="c1")
    assert client._APPROVED_CALLS == {}
    _answer("once", session_id="s1", tool_call_id="c1")
    assert list(client._APPROVED_CALLS) == [("s1", "c1")]
    observed = client.tool_execution(
        args={}, next_call=lambda _args: client._decision_fields(), session_id="s1", tool_call_id="c1"
    )
    assert observed == WITNESS_FIELDS
    assert client._APPROVED_CALLS == {} and client._RUNNING_CALLS == {} and client._CALL_SESSIONS == {}
    _refused(client._decision_fields)


def test_an_approval_left_from_a_call_that_never_ran_is_not_reused():
    # Recorded with no call running, and the call never entered the middleware.
    _answer("once", session_id="s1", tool_call_id="c1")
    # A later call with the same ids, hook first (model_tools.handle_function_call) ...
    client.bind_tool_session(WITNESS, session_id="s1", tool_call_id="c1")
    with pytest.raises(client.HandsError, match="nobody answered"):
        client.tool_execution(args={}, next_call=lambda _args: client._decision_fields(), session_id="s1", tool_call_id="c1")
    # ... or middleware first (the agent loop).
    _answer("once", session_id="s1", tool_call_id="c1")
    _refused(client._decision_fields)
    assert client._APPROVED_CALLS == {}


def test_an_unused_early_approval_expires_and_the_store_is_capped(monkeypatch):
    client._APPROVED_CALLS[("s1", "c1")] = client.time.monotonic() - client._APPROVAL_PENDING_FOR - 1
    client.bind_tool_session(WITNESS, session_id="s1", tool_call_id="c1")
    with pytest.raises(client.HandsError, match="nobody answered"):
        client.tool_execution(args={}, next_call=lambda _args: client._decision_fields(), session_id="s1", tool_call_id="c1")

    for index in range(4097):
        client.record_shown("s1", str(index), "terminal", {}, RULE_KEY)
        client.record_approval("s1", str(index), RULE_KEY)
    assert len(client._APPROVED_CALLS) == 4096 and ("s1", "0") not in client._APPROVED_CALLS
    clock = client.time.monotonic() + client._APPROVAL_PENDING_FOR + 1
    monkeypatch.setattr(client.time, "monotonic", lambda: clock)
    client.record_shown("s1", "late", "terminal", {}, RULE_KEY)
    client.record_approval("s1", "late", RULE_KEY)
    assert list(client._APPROVED_CALLS) == [("s1", "late")]


def test_a_failing_recorder_leaves_no_approval(monkeypatch, tmp_path):
    plugins = pytest.importorskip("hermes_cli.plugins")
    from hermes_cli.plugins_manifest import PluginManifest

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    manager = plugins.PluginManager()
    witness.register(plugins.PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager))

    def broken(session_id, tool_call_id, rule_key):
        raise RuntimeError("store failed")

    monkeypatch.setattr(client, "record_approval", broken)

    def body():
        # Core's dispatcher swallows an observer's error (plugins_dispatch.py), so the call goes on.
        manager.invoke_hook(
            "post_approval_response", choice="once", pattern_key=f"plugin_rule:{RULE_KEY}",
            session_id="s1", tool_call_id="c1",
        )
        return client._decision_fields()

    _refused(body)


def test_every_job_of_one_approved_call_runs():
    """write_file sends a pre-read, the write and a verify; terminal adds the snapshot bootstrap."""

    def body():
        _answer("once", session_id="s1", tool_call_id="c1")
        worker = contextvars.copy_context()
        jobs = [client._decision_fields() for _ in range(3)]
        thread = threading.Thread(target=worker.run, args=(lambda: jobs.append(client._decision_fields()),))
        thread.start()
        thread.join(5)
        return jobs

    assert _call(body) == [WITNESS_FIELDS] * 4


def test_a_normal_device_needs_no_approval():
    assert _call(client._decision_fields, device=NORMAL) == {"decision": {"device_id": "d2", "state": [False, "normal", None]}}


def _from_copied_context(monkeypatch, session_id="s1"):
    """A body whose context was copied before the middleware set its cell (Desktop terminal batch)."""
    pytest.importorskip("gateway.session_context")
    monkeypatch.setenv("HERMES_SESSION_ID", session_id)
    return contextvars.Context().run(client._decision_fields)


def test_a_body_without_its_cell_uses_the_sessions_only_running_call(monkeypatch):
    def body():
        _answer("once", session_id="s1", tool_call_id="c1")
        return _from_copied_context(monkeypatch)

    assert _call(body) == WITNESS_FIELDS
    _refused(lambda: _from_copied_context(monkeypatch))
    # No running call: nothing to find, so no decision, which the relay refuses for a witness device.
    assert _from_copied_context(monkeypatch) == {}


def test_a_body_without_its_cell_finds_nothing_while_several_calls_run(monkeypatch):
    def outer():
        _answer("once", session_id="s1", tool_call_id="c1")

        def inner():
            _answer("once", session_id="s1", tool_call_id="c2")
            return _from_copied_context(monkeypatch)

        return _call(inner, tool_call_id="c2")

    with pytest.raises(client.HandsError) as raised:
        _call(outer)
    assert str(raised.value) == messages.WITNESS_CALLS_OVERLAP
    # Several normal calls give no decision; the relay then uses the device's current session.
    assert _call(lambda: _call(lambda: _from_copied_context(monkeypatch), device=NORMAL, tool_call_id="c2"), device=NORMAL) == {}


def test_a_body_without_its_cell_claims_one_matching_approved_call(monkeypatch):
    """Two calls showing the same command, only the first answered: one body runs once, through the
    answered call; a second body finds no approved call left, and a different command none at all."""
    pytest.importorskip("gateway.session_context")
    monkeypatch.setenv("HERMES_SESSION_ID", "s1")
    shown = ("terminal", {"command": "echo same"})
    claims = []

    def claim(command):
        try:
            found = client.shown_call(lambda seen: seen == ("terminal", {"command": command}))
            claims.append((found, client._decision_fields()))
        except client.HandsError as exc:
            claims.append(str(exc))

    def outer():
        _answer("once", session_id="s1", tool_call_id="c1")

        def inner():
            for command in ("echo other", "echo same", "echo same"):
                contextvars.Context().run(claim, command)
            return client._CLAIMED_CALLS.copy()

        return _call(inner, tool_call_id="c2", shown=shown)

    assert _call(outer, shown=shown) == {("s1", "c1")}
    assert claims == [messages.WITNESS_CALL_CHANGED, (shown, WITNESS_FIELDS), messages.WITNESS_NOT_APPROVED]
    assert client._CLAIMED_CALLS == set() and client._RUNNING_CALLS == {}
