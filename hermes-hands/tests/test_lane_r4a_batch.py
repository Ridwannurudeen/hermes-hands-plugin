import contextvars
import json
import threading
from functools import partial
from types import SimpleNamespace

import pytest

from hands import client, store, targets
from hands_fakes import Device, hands_db, wired  # noqa: F401


@pytest.fixture(autouse=True)
def fresh_bindings(monkeypatch):
    monkeypatch.setattr(
        client, "_TOOL_SESSION", contextvars.ContextVar("r4a_tool_session", default=None)
    )
    monkeypatch.setattr(client, "_CALL_CELL", contextvars.ContextVar("r4a_call_cell", default=None))
    monkeypatch.setattr(client, "_RUNNING_CALLS", {})
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})
    monkeypatch.setattr(client, "_APPROVED_CALLS", {})
    monkeypatch.setattr(client, "_CLAIMED_CALLS", set())
    monkeypatch.setattr(targets, "_RAN", set())


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
        function=SimpleNamespace(name="terminal", arguments=json.dumps({"command": command, "timeout": 5})),
    )


@pytest.mark.parametrize(
    ("active", "denied", "commands", "ran"),
    [
        (False, False, ["echo one", "echo two"], None),
        (True, False, ["echo one", "echo two"], None),
        (True, False, ["echo same", "echo same"], None),
        (True, False, ["echo one", "echo two"], "echo other"),
        (True, True, ["echo one", "echo two"], None),
    ],
    ids=["normal", "active_witness", "active_witness_identical", "active_witness_changed", "active_witness_denied"],
)
def test_desktop_terminal_batch_carries_each_hook_decision_to_its_job(
    wired, monkeypatch, active, denied, commands, ran
):
    """Hermes Desktop prepares adjacent terminal calls in a batch (agent/terminal_approval_batch.py):
    bind_prepared_dispatch snapshots the context before the tool_execution middleware runs, so the
    tool body never sees the middleware's call cell, and every call of the batch is running while
    one body runs. A witness body claims the approved call whose shown arguments match what it runs,
    through the real HandsEnvironment.execute check, so each approval runs once; a body that runs a command no
    approved call showed is refused."""
    plugins = pytest.importorskip("hermes_cli.plugins")
    from agent import terminal_approval_batch, tool_executor
    from gateway import session_context
    from gateway.session_context import set_session_vars
    import model_tools
    import tools.approval as approval
    from tools.approval_context import _fire_approval_hook, set_current_session_key

    from hands import environment, messages, witness

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
    asked = []

    def answer(*args, rule_key, **kwargs):
        asked.append(args)
        choice = "deny" if denied else "once"
        _fire_approval_hook("post_approval_response", choice=choice, pattern_key=f"plugin_rule:{rule_key}")
        return {"approved": False, "message": "The helper said no."} if denied else {"approved": True}

    monkeypatch.setattr(approval, "request_tool_approval", answer)
    ctx = SimpleNamespace(current_cron_execution=lambda: None)
    manager = plugins.PluginManager(scope_key="r4a-desktop-batch")
    manager._middleware["tool_execution"] = [client.tool_execution]
    manager._hooks["pre_tool_call"] = [partial(witness.pre_tool_call, ctx)]
    manager._hooks["post_approval_response"] = [client.post_approval_response, witness.post_approval_response]
    manager._hooks["post_tool_call"] = [client.post_tool_call]
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)

    from test_environment import Ctx, FakeHandle

    env = environment.HandsEnvironment(Ctx(), cwd="~", timeout=5)
    seen, queued, sent = [], [], []
    post = client._post

    def observe(route, body, **kwargs):
        if route == "/local/exec":
            sent.append(body.get("decision"))
        return post(route, body, **kwargs)

    monkeypatch.setattr(client, "_post", observe)
    original_dispatch = model_tools.registry.dispatch

    def run_bash(sub, script, *, login=False, timeout=120, stdin_data=None):
        job = client.start_job("laptop", script=script, login=login, timeout=timeout, stdin=stdin_data)
        queued.append({"job": job})
        return FakeHandle("laptop", script, login=login, timeout=timeout, stdin=stdin_data)

    monkeypatch.setattr(environment.DeviceEnvironment, "_run_bash", run_bash)

    def dispatch(name, args, **kwargs):
        if name != "terminal":
            return original_dispatch(name, args, **kwargs)
        result = env.execute(ran or args["command"], "~", timeout=5, bounded_capture=True)
        seen.append(result["output"] if result["returncode"] else client._decision_fields())
        return json.dumps({"output": result["output"], "exit_code": result["returncode"]})

    monkeypatch.setattr(model_tools.registry, "dispatch", dispatch)
    session_key = "agent:main:desktop:dm:r4a"
    approval.register_gateway_notify(session_key, lambda _data: None)
    agent = _agent()
    calls = [_call("call-a", commands[0]), _call("call-b", commands[1])]
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
    assert client._RUNNING_CALLS == {} and client._CALL_SESSIONS == {} and client._APPROVED_CALLS == {}
    assert client._CLAIMED_CALLS == set()
    if denied:
        assert not targets.has_run(agent.session_id)
        assert not targets.is_pending(agent.session_id)
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
    if ran is not None:
        assert seen == [messages.WITNESS_CALL_CHANGED] * 2
        assert device.device_id not in hub._queues
        return
    assert seen == [decision, decision]
    assert queued and all(sorted(outcome) == ["job"] for outcome in queued), queued
    jobs = hub._queues[device.device_id]
    assert sent == [decision["decision"]] * len(queued), sent
    assert [next(command for command in commands if f"eval '{command}" in job["script"]) for job in jobs if "eval '" in job["script"]] == commands
