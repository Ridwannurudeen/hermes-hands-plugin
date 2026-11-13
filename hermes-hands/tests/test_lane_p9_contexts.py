"""Real Hermes approval contexts cannot authorize witness jobs without a human answer."""

import contextvars

import pytest

from hands import client, messages, witness
from test_witness_hardening import DEVICE, _agent


@pytest.mark.parametrize("mode", ["single_query", "cron", "unattended", "finite_turn", "normal"])
@pytest.mark.parametrize("setting", ["approve", "deny"])
def test_real_core_contexts_need_a_human_answer(monkeypatch, tmp_path, mode, setting):
    plugins = pytest.importorskip("hermes_cli.plugins")
    from agent import tool_executor
    from gateway.session_context import set_session_vars
    from gateway.session_finite import finite_turn_scope
    from hermes_cli.plugins_manifest import PluginManifest
    import tools.approval as approval
    from tools import approval_context, terminal_tool

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for name in (
        "HERMES_INTERACTIVE", "HERMES_EXEC_ASK", "HERMES_GATEWAY_SESSION", "HERMES_YOLO_MODE",
        "HERMES_SINGLE_QUERY_SESSION", "HERMES_CRON_SESSION", "HERMES_SESSION_PLATFORM",
        "HERMES_SESSION_KEY", "HERMES_SESSION_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    if mode == "single_query":
        monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
    if mode == "cron":
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    manager = plugins.PluginManager()
    ctx = plugins.PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager)
    witness.register(ctx)
    ctx.register_middleware("tool_execution", client.tool_execution)
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", False)
    config = {"mode": "manual", "single_query_mode": setting, "cron_mode": setting, "unattended_mode": setting}
    from hermes_cli import config as hermes_config

    monkeypatch.setattr(hermes_config, "load_config_readonly", lambda: {"approvals": config})
    answers, prompts, refused, jobs = [], [], [], []
    ctx.register_hook("post_approval_response", lambda **kwargs: answers.append(kwargs))

    def answer(*args, **kwargs):
        prompts.append(True)
        return "once"

    def execute(_args):
        try:
            fields = client._decision_fields()
        except client.HandsError as exc:
            refused.append(str(exc))
        else:
            jobs.append(fields)
        return "{}"

    def run():
        if mode == "unattended":
            set_session_vars(platform="api_server", source="api_server", session_key="api:p9", session_id="sess-1")
            approval_context.set_current_session_key("api:p9")
        else:
            approval_context.set_hermes_interactive_context(True)
            approval_context.set_current_session_key("cli:p9")
        terminal_tool.set_approval_callback(answer)
        try:
            with finite_turn_scope(mode == "finite_turn", unattended=mode == "finite_turn"):
                return tool_executor._run_sequential_tool_execution_middleware(
                    _agent(), function_name="terminal", function_args={"command": "touch notes"},
                    effective_task_id="task-p9", tool_call_id="call-p9", execute=execute,
                )
        finally:
            terminal_tool.set_approval_callback(None)

    result = contextvars.Context().run(run)
    assert client._RUNNING_CALLS == {} and client._APPROVED_CALLS == {}
    if mode == "normal":
        assert not result.blocked and refused == [] and prompts == [True]
        assert [(a["choice"], a["session_id"], a["tool_call_id"]) for a in answers] == [("once", "sess-1", "call-p9")]
        assert jobs == [{"decision": {"device_id": "device-id", "state": [True, "active", "serve-1"]}}]
    else:
        assert jobs == [] and prompts == [] and answers == []
        if setting == "deny" and mode != "finite_turn":
            assert result.blocked and refused == []
        else:
            assert not result.blocked and refused == [messages.WITNESS_NOT_APPROVED]
