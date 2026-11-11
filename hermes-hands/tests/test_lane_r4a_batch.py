import contextvars
import json
import threading
from functools import partial
from types import SimpleNamespace

import pytest

from hands import client, store
from hands_fakes import Device, hands_db, wired  # noqa: F401


@pytest.fixture(autouse=True)
def fresh_bindings(monkeypatch):
    monkeypatch.setattr(
        client, "_TOOL_SESSION", contextvars.ContextVar("r4a_tool_session", default=None)
    )
    monkeypatch.setattr(client, "_CALL_CELL", contextvars.ContextVar("r4a_call_cell", default=None))
    monkeypatch.setattr(client, "_RUNNING_CALLS", {})
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})


class _Guard:
    def before_call(self, name, args):
        return SimpleNamespace(allows_execution=True)


def _agent():
    return SimpleNamespace(
        session_id="desk-session",
        _current_turn_id="t1",
        _current_api_request_id="r1",
        _tool_guardrails=_Guard(),
        tool_progress_callback=None,
        _touch_activity=lambda *a, **k: None,
        _interrupt_requested=False,
        _tool_interrupt_reason=None,
        _tool_worker_threads=set(),
        _tool_worker_threads_lock=threading.Lock(),
        _context_engine_tool_names=set(),
        _memory_manager=None,
        valid_tool_names=None,
        enabled_toolsets=None,
        disabled_toolsets=None,
        quiet_mode=True,
        _should_emit_quiet_tool_messages=lambda: False,
        tool_start_callback=None,
        _checkpoint_mgr=SimpleNamespace(enabled=False),
        interrupt=lambda **k: None,
    )


def _call(call_id, command):
    return SimpleNamespace(
        id=call_id,
        type="function",
        function=SimpleNamespace(name="terminal", arguments=json.dumps({"command": command})),
    )


@pytest.mark.parametrize(
    ("active", "denied"),
    [(False, False), (True, False), (True, True)],
    ids=["normal", "active_witness", "active_witness_denied"],
)
def test_desktop_terminal_batch_carries_each_hook_decision_to_its_job(
    wired, monkeypatch, active, denied
):
    """Hermes Desktop prepares adjacent terminal calls in a batch (agent/terminal_approval_batch.py):
    bind_prepared_dispatch snapshots the context before the tool_execution middleware runs, so the
    tool body never sees the middleware's call cell. Each job must still carry its own decision."""
    plugins = pytest.importorskip("hermes_cli.plugins")
    from agent import terminal_approval_batch, tool_executor
    from gateway import session_context
    from gateway.session_context import set_session_vars
    import model_tools
    import tools.approval as approval
    from tools.approval_context import set_current_session_key

    from hands import environment, witness

    hub, _ = wired
    device = Device()
    store.record_seen(
        device.device_id,
        instance="serve-1",
        witness=active,
        session_state="active" if active else "normal",
        capabilities=["witness-v1", "checkup-v1"] if active else ["checkup-v1"],
    )
    monkeypatch.setattr(environment, "resolve_current_target", lambda _ctx: "laptop")
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    asked = []
    monkeypatch.setattr(
        approval,
        "request_tool_approval",
        lambda *a, **k: (
            asked.append(a)
            or (
                {"approved": False, "message": "The helper said no."}
                if denied
                else {"approved": True}
            )
        ),
    )
    ctx = SimpleNamespace(current_cron_execution=lambda: None)
    manager = plugins.PluginManager(scope_key="r4a-desktop-batch")
    manager._middleware["tool_execution"] = [client.tool_execution]
    manager._hooks["pre_tool_call"] = [partial(witness.pre_tool_call, ctx)]
    ctx._manager = manager  # the real _other_hooks check
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)

    seen, queued = [], []
    original_dispatch = model_tools.registry.dispatch

    def dispatch(name, args, **kwargs):
        if name != "terminal":
            return original_dispatch(name, args, **kwargs)
        seen.append(client._decision_fields())
        # The device handle queues its job from a context copied inside the tool (hands/handle.py).
        worker = contextvars.copy_context()
        outcome = {}

        def queue():
            try:
                outcome["job"] = client.start_job(
                    "laptop", script=args["command"], login=False, timeout=5
                )
            except client.HandsError as exc:
                outcome["refused"] = str(exc)

        thread = threading.Thread(target=worker.run, args=(queue,))
        thread.start()
        thread.join(10)
        queued.append(outcome)
        return json.dumps({"output": json.dumps(outcome), "exit_code": 0})

    monkeypatch.setattr(model_tools.registry, "dispatch", dispatch)
    session_key = "agent:main:desktop:dm:r4a"
    approval.register_gateway_notify(session_key, lambda _data: None)
    agent = _agent()
    calls = [_call("call-a", "echo one"), _call("call-b", "echo two")]
    results = []

    def run_batch():
        # Session vars stay in this copied context, so later tests see none of them.
        set_session_vars(source="desktop", session_key=session_key, session_id=agent.session_id)
        set_current_session_key(session_key)
        with terminal_approval_batch.terminal_approval_batch(agent, calls, [], "task"):
            assert terminal_approval_batch._batch.get() is not None, (
                "the desktop batch did not start"
            )
            for call in calls:
                ref = tool_executor._parse_tool_call(agent, call).ref("task")
                results.append(
                    tool_executor._run_sequential_tool_execution_middleware(
                        agent,
                        **ref.middleware_kwargs(),
                        execute=lambda _args: pytest.fail("a prepared slot runs its own dispatch"),
                    )
                )

    monkeypatch.setattr(
        session_context, "_session_context_engaged", session_context._session_context_engaged
    )
    try:
        contextvars.copy_context().run(run_batch)
    finally:
        approval.unregister_gateway_notify(session_key)

    assert len(asked) == (2 if active else 0)
    assert client._RUNNING_CALLS == {} and client._CALL_SESSIONS == {}
    if denied:
        assert [result.blocked for result in results] == [True, True], [r.result for r in results]
        assert seen == [] and queued == []
        assert device.device_id not in hub._queues
        return
    decision = {
        "decision": {
            "device_id": device.device_id,
            "state": [active, "active" if active else "normal", "serve-1" if active else None],
        }
    }
    assert [result.blocked for result in results] == [False, False], [r.result for r in results]
    assert seen == [decision, decision]
    assert [sorted(outcome) for outcome in queued] == [["job"], ["job"]], queued
    assert [job["script"] for job in hub._queues[device.device_id]] == ["echo one", "echo two"]
