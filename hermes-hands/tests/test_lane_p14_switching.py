"""Switching retains begun operations, releasing declined first attempts."""

import contextvars

import pytest

from hands import client, commands, store, targets
from hands_fakes import hands_db, wired  # noqa: F401
from test_commands import Context
from test_environment import (  # noqa: F401
    fresh_session_cwds, hands_backend, isolated_hermes_home, laptop,
)
from test_lane_p8_findings import dispatch  # noqa: F401
from test_lane_r3b1_agent_loop import _agent


@pytest.mark.parametrize("veto", ["decline", "refuse"])
def test_preexecution_veto_releases_switching_but_a_real_device_command_locks(
    dispatch, monkeypatch, veto
):
    import model_tools
    from agent import tool_executor
    from tools import approval_context, terminal_tool

    d = dispatch
    monkeypatch.setattr(targets, "_RAN", set())
    monkeypatch.setenv("HERMES_SESSION_ID", "sess-1")
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    original_get = store.get_device
    monkeypatch.setattr(store, "get_device", lambda name: original_get("laptop" if name == "other" else name))
    ctx = Context()
    ctx.config["default_target"] = "laptop"
    commands.register_commands(ctx, has_seed=True)
    store.set_session_target("cli:sess-1", "laptop", owner=targets.LOCAL)
    agent = _agent()
    agent.session_id = "sess-1"
    if veto == "refuse":
        d.before = {"action": "block", "message": "Refused before dispatch"}
    asked = []

    def answer(*args, **kwargs):
        asked.append(args)
        assert not targets.has_run("sess-1")
        assert targets.is_pending("sess-1")
        pending = ctx.handler("use other", session_id="sess-1", session_key="cli:sess-1", platform="cli")
        assert "still in progress" in pending and "/new" not in pending
        return "deny"

    def run():
        approval_context.set_hermes_interactive_context(True)
        approval_context.set_current_session_key("cli:sess-1")
        terminal_tool.set_approval_callback(answer)
        try:
            return tool_executor._run_agent_tool_execution_middleware(
                agent, function_name="terminal", function_args={"command": "echo approved"},
                effective_task_id="p8", tool_call_id="veto-1",
                execute=lambda args: model_tools.handle_function_call(
                    "terminal", args, task_id="p8", tool_call_id="veto-1", session_id="sess-1",
                    skip_pre_tool_call_hook=True, skip_tool_execution_middleware=True,
                ),
                begin_execution=lambda cb=None: None,
            )
        finally:
            terminal_tool.set_approval_callback(None)

    managed = contextvars.copy_context().run(run)
    assert managed.blocked, managed.result
    assert ("Refused before dispatch" if veto == "refuse" else "denied") in managed.result
    assert bool(asked) == (veto == "decline")
    assert d.jobs == []
    assert not targets.has_run("sess-1") and not targets.is_pending("sess-1")
    assert ctx.handler(
        "use other", session_id="sess-1", session_key="cli:sess-1", platform="cli"
    ).startswith("Target set to other")
    store.set_session_target("cli:sess-1", "laptop", owner=targets.LOCAL)
    d.before = None
    result = d.call("terminal", {"command": "echo approved"})
    assert d.jobs and "approved" in result
    assert targets.has_run("sess-1")
    assert "/new" in ctx.handler(
        "use other", session_id="sess-1", session_key="cli:sess-1", platform="cli"
    )
    assert store.get_session_target("cli:sess-1")[0] == "laptop"
