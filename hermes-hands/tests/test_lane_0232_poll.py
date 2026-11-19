"""Both registry poll protocols stay bound to the launch's device and artifacts."""

import inspect

import pytest

pytest.importorskip("tools.environments.base")

from hands import environment, messages, store  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    Ctx,
    FakeSub,
    fresh_session_cwds,
    isolated_hermes_home,
    laptop,
)


@pytest.fixture
def job(laptop):
    env = environment.HandsEnvironment(Ctx(), cwd="~", timeout=30)
    device, desk = FakeSub([]), FakeSub([])
    env._subs = {"laptop": device, "desk": desk}
    artifacts = tuple(f"/tmp/hermes_bg_proc_123456789abc.{ext}" for ext in ("log", "exit", "pid"))
    env._record_background("proc_123456789abc", "laptop", {"output": "4242\n"}, artifacts)
    store.set_session_target("s1", "desk")
    return env, device, desk, artifacts


@pytest.mark.parametrize("exit_code", ["0", "7", ""])
@pytest.mark.parametrize("returncode", [0, 1])
def test_combined_run_and_final_delta_are_unchanged_and_release_the_route(job, monkeypatch, exit_code, returncode):
    env, device, desk, (log, exited, pid) = job
    running = "11 0 run\n0 0 exit:0\n"
    final = f"15 11 exit:{exit_code}\nlast"
    replies = iter((running, final))

    def execute(command, cwd="", **kwargs):
        device.commands.append(command)
        return {"output": next(replies), "returncode": returncode}

    monkeypatch.setattr(device, "execute", execute)
    for offset, output in ((0, running), (11, final)):
        command = environment._log_delta_command(log, offset, pid, exited)
        assert environment._registry_command(command) == ("log", "proc_123456789abc")
        assert env.execute(command, timeout=10) == {"output": output, "returncode": returncode}
        assert device.commands[-1] == command and desk.commands == []
        if offset == 0:
            assert "proc_123456789abc" in env._background
    assert env._background == env._background_pids == env._background_artifacts == {}
    with pytest.raises(RuntimeError, match=messages.BACKGROUND_JOB_ENDED):
        env.execute(command, timeout=10)
    assert len(device.commands) == 2 and desk.commands == []


@pytest.mark.parametrize("mutation", ["suffix", "offset", "status", "other-job"])
def test_a_combined_lookalike_is_never_a_registry_poll(job, mutation):
    env, device, desk, (log, exited, pid) = job
    command = environment._log_delta_command(log, 0, pid, exited)
    command = {
        "suffix": command + "; touch /tmp/owned",
        "offset": command.replace("O=0;", "O=00;"),
        "status": command.replace("then T=run;", "then T=exit:0;"),
        "other-job": command.replace(pid, pid.replace("123456789abc", "abcdef123456")),
    }[mutation]
    assert environment._registry_command(command) is None
    env.execute(command, timeout=10)
    assert desk.commands == [command] and device.commands == []


@pytest.mark.parametrize("artifact", ["log", "pid", "exit"])
def test_a_combined_poll_cannot_read_unrecorded_artifacts(job, artifact):
    env, device, desk, (log, exited, pid) = job
    paths = {"log": log, "pid": pid, "exit": exited}
    paths[artifact] = paths[artifact].replace("/tmp/", "/other/")
    command = environment._log_delta_command(paths["log"], 0, paths["pid"], paths["exit"])
    assert env.execute(command, timeout=10) == {
        "output": messages.WITNESS_CALL_CHANGED, "returncode": 255,
    }
    assert device.commands == desk.commands == []


@pytest.mark.parametrize("gone", [messages.unknown_device("laptop"), messages.revoked("laptop"), messages.NOT_SET_UP])
def test_a_combined_poll_and_its_fallback_never_reach_the_current_target(job, monkeypatch, gone):
    env, device, desk, (log, exited, pid) = job

    def execute(command, cwd="", **kwargs):
        device.commands.append(command)
        return {"output": gone, "returncode": 255}

    monkeypatch.setattr(device, "execute", execute)
    combined = environment._log_delta_command(log, 0, pid, exited)
    assert env.execute(combined, timeout=10)["output"] == gone
    probe = f'kill -0 "$(cat {pid} 2>/dev/null)" 2>/dev/null; echo $?'
    with pytest.raises(RuntimeError):
        env.execute(probe, timeout=5)
    for command, timeout in ((combined, 10), (probe, 5), (f"cat {exited} 2>/dev/null", 5)):
        with pytest.raises(RuntimeError):
            env.execute(command, timeout=timeout)
    assert device.commands == [combined, probe] and desk.commands == []


@pytest.mark.parametrize("fallback_alive", [True, False])
def test_real_core_poller_recovers_an_unreadable_reply_on_the_jobs_device(laptop, monkeypatch, fallback_alive):
    from tools.process_registry import ProcessRegistry
    from tools.process_registry_env_log import log_delta_command

    env = environment.HandsEnvironment(Ctx(), cwd="~", timeout=30)
    device, desk = FakeSub([4242]), FakeSub([])
    env._subs = {"laptop": device, "desk": desk}
    registry = ProcessRegistry()
    readers = []
    monkeypatch.setattr(registry, "_track_started", lambda session, reader, name, extra_args=(): readers.append((reader, extra_args)))
    session = registry.spawn_via_env(env, "sleep 600", task_id="poll-fallback")
    store.set_session_target("s1", "desk")
    commands = []
    combined = "quoted_pid_path" in inspect.signature(log_delta_command).parameters
    # The last valid run already delivered the complete output before a mangled exit reply.
    replies = iter(
        (["5 0 run\nfirst", "garbage", "0", "9 5 exit:7\nlast"] if fallback_alive else
         ["9 0 run\nfirstlast", "garbage", "1", "7"])
        if combined else
        (["5 0\nfirst", "0", "garbage", "0", "9 5\nlast", "1", "7"] if fallback_alive else
         ["9 0\nfirstlast", "0", "garbage", "1", "7"])
    )

    def execute(command, cwd="", **kwargs):
        commands.append(command)
        return {"output": next(replies), "returncode": 0}

    monkeypatch.setattr(device, "execute", execute)
    reader, extra_args = readers[0]
    reader(session, *extra_args)
    assert session.exited and session.exit_code == 7 and session.completion_reason == "exited"
    assert session.output_buffer == "firstlast"
    assert desk.commands == [] and env._background == env._background_pids == {}
    kinds = [environment._registry_command(command)[0] for command in commands]
    expected = (["log", "log", "probe", "log"] if fallback_alive else ["log", "log", "probe", "exit"]) if combined else (
        ["log", "probe", "log", "probe", "log", "probe", "exit"] if fallback_alive else ["log", "probe", "log", "probe", "exit"]
    )
    assert kinds == expected
