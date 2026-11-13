"""Approved terminal deadlines remain exact through core, relay and device execution."""

import contextvars
import json
import threading
import time

import pytest

pytest.importorskip("tools.environments.base")

from hands import client, environment, messages
from hands_fakes import hands_db, wired  # noqa: F401
from test_environment import (  # noqa: F401
    fresh_session_cwds, hands_backend, isolated_hermes_home, laptop,
)
from test_lane_p8_findings import dispatch  # noqa: F401
from test_lane_r3b1_agent_loop import _agent
from test_e2e_device_relay import (  # noqa: F401
    rig, _witness_agent, device_executor, until,
)


@pytest.mark.parametrize("timeout_args", [{}, {"timeout": None}])
@pytest.mark.parametrize("agent_path", [False, True], ids=["model-dispatch", "agent-dispatch"])
def test_scoped_timeout_uses_one_explicit_approved_default(dispatch, monkeypatch, timeout_args, agent_path):
    from hermes_cli import config
    from tools import approval_context, terminal_scope, terminal_tool
    from agent import tool_executor
    import model_tools

    d = dispatch
    bridges = []

    def bridge(*, env):
        bridges.append(env)
        return {**env, "TERMINAL_TIMEOUT": "180"}

    monkeypatch.setattr(config, "apply_terminal_config_to_env", bridge)
    args = {"command": "pwd", **timeout_args}
    scope = terminal_scope.set_terminal_scope({"TERMINAL_ENV": "hands", "TERMINAL_TIMEOUT": "47"})
    try:
        if agent_path:
            agent = _agent()
            agent.session_id = "sess-1"

            def answer(command, description, **kwargs):
                d.cards.append(description)
                return "once"

            def run():
                approval_context.set_hermes_interactive_context(True)
                approval_context.set_current_session_key("cli:sess-1")
                terminal_tool.set_approval_callback(answer)
                try:
                    return tool_executor._run_agent_tool_execution_middleware(
                        agent, function_name="terminal", function_args=args,
                        effective_task_id="p8", tool_call_id="explicit-default",
                        execute=lambda effective: model_tools.handle_function_call(
                            "terminal", effective, task_id="p8", tool_call_id="explicit-default",
                            session_id="sess-1", skip_pre_tool_call_hook=True,
                            skip_tool_execution_middleware=True,
                        ), begin_execution=lambda cb=None: None,
                    ).result
                finally:
                    terminal_tool.set_approval_callback(None)

            result = contextvars.copy_context().run(run)
        else:
            result = d.call("terminal", args)
        assert messages.WITNESS_CALL_CHANGED not in result, result
        assert d.base in result and d.jobs, (result, d.outputs)
        assert "timeout=180" in d.cards[0]
        assert len(bridges) == 1
        assert d.jobs[-1]["timeout"] == 180
        assert args == {"command": "pwd", **timeout_args}
        d.jobs.clear()
        d.modify = lambda effective: {**effective, "timeout": 181}
        changed = d.call("terminal", args)
        assert messages.WITNESS_CALL_CHANGED in changed
        assert d.jobs == []
    finally:
        terminal_scope.reset_terminal_scope(scope)


def test_registered_terminal_sends_exact_approved_timeout_to_relay(dispatch):
    d = dispatch
    result = d.call("terminal", {"command": "pwd", "timeout": 1})
    assert d.base in result, result
    assert "timeout=1" in d.cards[0]
    assert d.jobs[-1]["timeout"] == 1


def test_registered_terminal_device_deadline_does_not_depend_on_gateway_cancel(rig, monkeypatch):
    from agent import terminal_env_registry
    from hermes_cli import plugins
    from hermes_cli.plugins_manifest import PluginManifest
    from tools import approval_context, terminal_tool
    import model_tools

    witness_loop, witness_thread, errors = _witness_agent(rig)
    hands = rig.hands
    manager = plugins.PluginManager()
    ctx = plugins.PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager)
    hands.witness.register(ctx)
    ctx.register_middleware("tool_execution", hands.client.tool_execution)
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)
    provider = next(value for name, value in rig.context.calls if name == "terminal")
    previous = terminal_env_registry.snapshot_registration("hands")
    terminal_env_registry.register_provider(provider)
    monkeypatch.setenv("TERMINAL_ENV", "hands")
    rig.context.config["default_target"] = "laptop"
    monkeypatch.setattr(hands.client, "cancel_job", lambda job: None)
    cards, execution, outcome = [], [], []
    original_run = device_executor.run

    def observe(script, **kwargs):
        started = time.monotonic()
        job = kwargs["job_id"]
        execution.append({"timeout": kwargs["timeout"], "deadline": witness_loop.job_deadlines[job] - started})
        codes = []
        on_exit = kwargs["on_exit"]

        def exit_code(code):
            codes.append(code)
            on_exit(code)

        yield from original_run(script, **{**kwargs, "on_exit": exit_code})
        execution[-1].update(elapsed=time.monotonic() - started, codes=codes)

    monkeypatch.setattr(device_executor, "run", observe)

    def run():
        approval_context.set_hermes_interactive_context(True)
        approval_context.set_current_session_key("cli:s1")
        terminal_tool.set_approval_callback(lambda command, description, **kwargs: cards.append(description) or "once")
        try:
            outcome.append(model_tools.handle_function_call(
                "terminal", {"command": "sleep 10", "timeout": 1},
                task_id="p15-device-deadline", session_id="s1", tool_call_id="deadline-1",
            ))
        finally:
            terminal_tool.set_approval_callback(None)

    worker = threading.Thread(target=run)
    try:
        worker.start()
        until(lambda: any("sleep 10" in job.get("script", "") for job in rig.delivered), what="approved job")
        [job] = [job for job in rig.delivered if "sleep 10" in job.get("script", "")]
        assert "timeout=1" in cards[0]
        assert job["timeout"] == 1
        until(lambda: execution and "codes" in execution[-1], what="device deadline to terminate job", timeout=8)
        assert execution[-1]["timeout"] == 1
        assert 0 < execution[-1]["deadline"] <= 1
        assert execution[-1]["codes"] == [124]
        assert execution[-1]["elapsed"] < 6
        worker.join(10)
        assert not worker.is_alive() and outcome
    finally:
        witness_loop._stop_from_console()
        witness_thread.join(10)
        worker.join(10)
        terminal_env_registry.restore_registration("hands", provider, previous)
        for key, env in list(terminal_tool._active_environments.items()):
            if isinstance(env, hands.environment.HandsEnvironment):
                terminal_tool._active_environments.pop(key, None)
                env.cleanup()
    assert errors == []


@pytest.mark.parametrize("workdir", ["C:/work", "/C:/work", "/c/work"])
def test_posix_workdir_keeps_approved_spelling_in_final_job(dispatch, monkeypatch, workdir):
    from hands import store
    import test_lane_p8_findings
    from test_environment import bash_job

    d = dispatch
    device = store.get_device("laptop")
    monkeypatch.setattr(store, "get_device", lambda name: {**device, "os": "Linux"})
    destinations = {"C:/work": "work", "/C:/work": "workspace", "/c/work": "archive"}

    def posix_job(job):
        # Give the Windows-hosted bash device distinct POSIX destinations, including a colon.
        script = job["script"]
        for path, folder in destinations.items():
            script = script.replace("builtin cd -- " + path + " || exit 126", "builtin cd -- " + d.base + "/" + folder + " || exit 126")
        return bash_job({**job, "script": script})

    monkeypatch.setattr(test_lane_p8_findings, "bash_job", posix_job)
    result = d.call("terminal", {"command": "touch approved.txt", "workdir": workdir, "timeout": 10})
    assert messages.WITNESS_CALL_CHANGED not in result, result
    jobs = [job for job in d.jobs if "touch approved.txt" in job["script"]]
    assert len(jobs) == 1
    assert "builtin cd -- " + workdir + " || exit 126" in jobs[0]["script"], jobs
    assert (d.home / destinations[workdir] / "approved.txt").exists(), (result, d.outputs)
    assert all(not (d.home / folder / "approved.txt").exists() for path, folder in destinations.items() if path != workdir)


@pytest.mark.parametrize("timeout", [1, 10, None])
def test_background_explicit_timeout_is_refused_before_approval(dispatch, timeout):
    d = dispatch
    result = d.invoke("terminal", {"command": "sleep 20", "background": True, "timeout": timeout})
    assert "a background command has no time limit: leave out timeout; press S to stop it" in result
    assert d.cards == [] and d.answers == [] and d.jobs == []


def test_background_without_timeout_has_truthful_card(dispatch, monkeypatch):
    from tools.process_registry import process_registry

    d = dispatch
    sessions = []
    monkeypatch.setattr(process_registry, "_track_started", lambda session, *args, **kwargs: sessions.append(session))
    result = json.loads(d.call("terminal", {"command": "pwd", "background": True}))
    try:
        assert result.get("session_id"), (result, d.outputs)
        assert "background=true" in d.cards[0]
        assert "no time limit" in d.cards[0] and "press S to stop it" in d.cards[0]
        assert "timeout" not in d.cards[0].lower()
        assert d.jobs and any("nohup bash -lc pwd" in job["script"] for job in d.jobs)
    finally:
        with process_registry._lock:
            for session in sessions:
                process_registry._running.pop(session.id, None)
                process_registry._finished.pop(session.id, None)


@pytest.mark.parametrize("changes", [{"background": False}, {"background": False, "timeout": 1}])
def test_background_card_cannot_be_changed_to_foreground(dispatch, changes):
    d = dispatch
    d.modify = lambda effective: {"command": effective["command"], **changes}
    result = d.call("terminal", {"command": "pwd", "background": True})
    assert messages.WITNESS_CALL_CHANGED in result and d.jobs == []
    assert "KeyError" not in result
    assert "background=true" in d.cards[0] and "no time limit" in d.cards[0]
    assert "timeout" not in d.cards[0].lower()
