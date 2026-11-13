"""Core-built background polls retain the launch's approval and device artifacts."""

import contextvars
import json

import pytest

pytest.importorskip("tools.environments.base")

from hands import environment, messages  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401


def test_real_registry_launch_and_polls_reach_the_device_unchanged(dispatch, monkeypatch):
    from tools.environments.base_session_env import _eval_capturing_pipestatus
    from tools.process_registry import process_registry

    d = dispatch
    readers = []
    calls = []
    execute = environment.HandsEnvironment.execute

    def track(session, reader, name, extra_args=()):
        readers.append((contextvars.copy_context(), session, reader, extra_args))

    def capture(env, command, cwd="", **kwargs):
        # Bound the real poller if the test device cannot report process exit.
        assert len(calls) < 16, calls
        before = len(d.jobs)
        result = execute(env, command, cwd, **kwargs)
        calls.append((command, cwd, kwargs, result, list(d.jobs[before:])))
        return result

    monkeypatch.setattr(process_registry, "_track_started", track)
    monkeypatch.setattr(environment.HandsEnvironment, "execute", capture)
    result = json.loads(d.call("terminal", {"command": "pwd", "background": True}))
    assert "background=true" in d.cards[0] and "no time limit" in d.cards[0]
    assert "timeout" not in d.cards[0].lower()
    assert result.get("session_id"), (result, d.outputs)
    assert len(readers) == 1
    context, session, reader, extra_args = readers[0]
    assert session.id == result["session_id"]
    try:
        context.run(reader, session, *extra_args)
        assert session.exited and session.exit_code == 0, (session, calls, d.outputs)
        assert d.base in session.output_buffer, (session.output_buffer, d.outputs)
        kinds = [
            "launch" if environment._LAUNCH_WRAPPER.fullmatch(command)
            else environment._registry_command(command)[0]
            for command, *_ in calls
        ]
        assert kinds[0] == "launch" and kinds[-1] == "exit", kinds
        assert set(kinds) == {"launch", "log", "probe", "exit"}, kinds
        for command, cwd, kwargs, execution, jobs in calls:
            assert messages.WITNESS_CALL_CHANGED not in execution["output"], (command, execution)
            assert jobs, (command, execution)
            # The final relay job embeds the exact command captured from core,
            # including its canonical log/exit/PID destination and byte offset.
            escaped = command.replace("'", "'\\''")
            script = jobs[-1]["script"]
            expected = _eval_capturing_pipestatus(escaped)
            assert expected in script or f"eval '{escaped}'\n__hermes_ec=$?" in script, jobs[-1]
            assert jobs[-1]["timeout"] == kwargs["timeout"], jobs[-1]
            assert jobs[-1].get("stdin") is None
    finally:
        with process_registry._lock:
            process_registry._running.pop(session.id, None)
            process_registry._finished.pop(session.id, None)
