import contextvars
import threading
from functools import partial
from types import SimpleNamespace

import pytest

from hands import client, store
from hands_fakes import Device, hands_db, wired  # noqa: F401


@pytest.fixture(autouse=True)
def fresh_bindings(monkeypatch):
    monkeypatch.setattr(
        client, "_TOOL_SESSION", contextvars.ContextVar("r3b1_tool_session", default=None)
    )
    monkeypatch.setattr(
        client, "_CALL_CELL", contextvars.ContextVar("r3b1_call_cell", default=None), raising=False
    )
    monkeypatch.setattr(client, "_RUNNING_CALLS", {}, raising=False)
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})
    monkeypatch.setattr(client, "_APPROVED_CALLS", {})


class _Guard:
    def before_call(self, name, args):
        return SimpleNamespace(allows_execution=True)


def _agent():
    return SimpleNamespace(
        session_id="agent-1",
        _current_turn_id="t1",
        _current_api_request_id="r1",
        _tool_guardrails=_Guard(),
        tool_progress_callback=None,
        _touch_activity=lambda *a, **k: None,
        _interrupt_requested=False,
    )


@pytest.mark.parametrize("active", [False, True], ids=["normal", "active_witness"])
@pytest.mark.parametrize("tool", ["terminal", "hands_checkup"])
def test_agent_loop_executor_runs_the_hook_inside_the_middleware_and_queues_the_job(
    wired, monkeypatch, active, tool
):
    """agent/tool_executor.py runs pre_tool_call inside next_call of the tool_execution middleware,
    so the decision the hook binds must still reach the tool body after the middleware has started."""
    plugins = pytest.importorskip("hermes_cli.plugins")
    from agent import tool_executor
    from gateway.session_context import scoped_session_key
    import tools.approval as approval
    from tools.approval_context import _fire_approval_hook

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
    asked = []

    def human_yes(*args, rule_key, **kwargs):
        # The person's answer, reported the way core's prompt reports it (tools/approval.py).
        asked.append(args)
        _fire_approval_hook("post_approval_response", choice="once", pattern_key=f"plugin_rule:{rule_key}")
        return {"approved": True}

    monkeypatch.setattr(approval, "request_tool_approval", human_yes)
    ctx = SimpleNamespace(current_cron_execution=lambda: None)
    manager = plugins.PluginManager(scope_key="r3b1-agent-loop")
    manager._middleware["tool_execution"] = [client.tool_execution]
    manager._hooks["pre_tool_call"] = [partial(witness.pre_tool_call, ctx)]
    manager._hooks["post_approval_response"] = [witness.post_approval_response]
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)
    seen = []

    def execute(_args):
        seen.append(client._decision_fields())
        if tool == "hands_checkup":
            return client._post(
                "/local/exec", {"device": "laptop", "type": "checkup", **client._decision_fields()}
            )
        return client.start_job("laptop", script="echo check", login=False, timeout=5)

    with scoped_session_key("route-1"):
        managed = tool_executor._run_agent_tool_execution_middleware(
            _agent(),
            function_name=tool,
            function_args={"command": "echo check"} if tool == "terminal" else {},
            effective_task_id="task",
            tool_call_id="call-1",
            execute=execute,
            begin_execution=lambda cb=None: None,
        )

    assert not managed.blocked, managed.result
    assert seen == [
        {
            "decision": {
                "device_id": device.device_id,
                "state": [active, "active" if active else "normal", "serve-1" if active else None],
            },
        }
    ]
    assert len(hub._jobs) == 1, managed.result
    assert bool(asked) == active
    assert client._CALL_SESSIONS == {} and client._APPROVED_CALLS == {}
    assert client._decision_fields() == {}


def test_a_worker_thread_started_by_the_tool_keeps_the_decision_after_the_call_returns(hands_db):
    """RemoteProcessHandle queues its job from a copied context; that must not race the middleware's
    cleanup of the shared binding."""
    device = Device()
    snapshot = store.device_by_id(device.device_id)
    release, read = threading.Event(), []

    def tool_body(_args):
        client.bind_tool_session(snapshot, session_id="s1", tool_call_id="c1")
        worker = contextvars.copy_context()
        thread = threading.Thread(
            target=worker.run,
            args=(lambda: (release.wait(5), read.append(client._decision_fields())),),
        )
        thread.start()
        return thread

    thread = client.tool_execution(args={}, next_call=tool_body, session_id="s1", tool_call_id="c1")
    assert client._CALL_SESSIONS == {}
    release.set()
    thread.join(5)
    assert read == [{"decision": {"device_id": device.device_id, "state": [False, "normal", None]}}]


def test_a_flood_of_other_bindings_cannot_evict_a_running_call_before_its_hook_binds(hands_db):
    """The middleware starts before the hook in the agent loop; the hook then writes into the running
    call's own binding, which later calls cannot push out of the cache."""
    first, second = Device("first"), Device("second")
    first_snapshot = store.device_by_id(first.device_id)
    second_snapshot = store.device_by_id(second.device_id)

    def tool_body(_args):
        for index in range(4096):
            client.bind_tool_session(second_snapshot, session_id="other", tool_call_id=str(index))
        client.bind_tool_session(first_snapshot, session_id="s1", tool_call_id="c1")
        return client._decision_fields()

    observed = client.tool_execution(
        args={}, next_call=tool_body, session_id="s1", tool_call_id="c1"
    )
    assert observed == {
        "decision": {"device_id": first.device_id, "state": [False, "normal", None]}
    }
    assert ("s1", "c1") not in client._CALL_SESSIONS
    assert len(client._CALL_SESSIONS) == 4096
