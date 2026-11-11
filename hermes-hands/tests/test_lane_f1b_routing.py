"""Background-job routing, MEDIA fetches and oversized-result spills against real Hermes core: only
core's own registry commands follow a job to its device, and an active witness device gets no
unapproved fetch or spill."""

import pytest

pytest.importorskip("tools.environments.base")
pytest.importorskip("gateway.session_context")
pytest.importorskip("agent.terminal_env_provider")

from tools.environments.base import BaseEnvironment, FileFetchError  # noqa: E402

from hands import store  # noqa: E402
from hands.environment import HandsEnvironment  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401  (fixtures)
from test_environment import (  # noqa: E402,F401  (fixtures)
    Ctx,
    FakeSub,
    end_jobs,
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)


class FileSub(FakeSub):
    """A FakeSub the file tools can drive."""

    env: dict = {}
    is_local = False
    uses_host_filesystem = False


class Recorder(BaseEnvironment):
    """A device sub-environment that records each command and runs nothing."""

    def __init__(self):
        super().__init__(cwd="/c/Users/x", timeout=5)
        self.commands = []

    def execute(self, command, cwd="", **kwargs):
        self.commands.append(command)
        return {"output": "", "returncode": 1}

    def cleanup(self):
        pass


def as_file_tool(env, command):
    """Run ``env.execute`` from a frame core's file-tool modules own (file_operations.py:229-239)."""
    scope = {"__name__": "tools.file_operations_probe", "env": env, "command": command}
    exec("result = env.execute(command)", scope)
    return scope["result"]


def witness_on(monkeypatch, active=True):
    monkeypatch.setattr(
        store,
        "device_by_id",
        lambda device_id: {
            "name": "laptop",
            "witness": active,
            "session_state": "active",
            "capabilities": ["witness-v1"],
        },
    )


def test_file_tools_on_another_target_never_reach_a_jobs_device(laptop):
    from tools.file_operations import ShellFileOperations
    from tools.process_registry import process_registry

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    jobs, desk = FileSub([4242]), FileSub([])
    env._subs = {"laptop": jobs, "desk": desk}
    sessions = []
    try:
        sessions.append(process_registry.spawn_via_env(env, "sleep 600", task_id="bg-a"))
        job = sessions[0].id
        store.set_session_target("s1", "desk")
        startup = f"/c/Users/her/Start Menu/Programs/Startup/hermes_bg_{job}.log.cmd"
        ShellFileOperations(env).write_file(startup, "calc")
        ShellFileOperations(env).read_file(f"/tmp/hermes_bg_{job}.exit")
        ShellFileOperations(env).search(job, path=f"/tmp/hermes_bg_{job}.log")
        # read_file's exact shape for the exit file is also core's exit read (process_registry.py:1465)
        as_file_tool(env, f"cat /tmp/hermes_bg_{job}.exit 2>/dev/null")
        assert not any("Startup" in command or "calc" in command for command in jobs.commands)
        assert f"cat /tmp/hermes_bg_{job}.exit 2>/dev/null" not in jobs.commands
        assert any("Startup" in command for command in desk.commands)
        assert f"cat /tmp/hermes_bg_{job}.exit 2>/dev/null" in desk.commands
    finally:
        end_jobs(sessions, jobs, desk)


def test_only_cores_exact_registry_commands_follow_a_job(laptop):
    from tools.process_registry import process_registry
    from tools.process_registry_env_log import log_delta_command

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    jobs, desk = FakeSub([4242]), FakeSub([])
    env._subs = {"laptop": jobs, "desk": desk}
    sessions = []
    try:
        sessions.append(process_registry.spawn_via_env(env, "sleep 600", task_id="bg-b"))
        job = sessions[0].id
        store.set_session_target("s1", "desk")
        for command in (
            f"cat /tmp/hermes_bg_{job}.exit 2>/dev/null; touch /tmp/owned",
            f"cat /tmp/hermes_bg_{job}.log.cmd 2>/dev/null",
            f"echo x > /tmp/hermes_bg_{job}.pid",
            f'kill -0 "$(cat /tmp/hermes_bg_{job}.exit 2>/dev/null)" 2>/dev/null; echo $?',
            "kill 4242 2>/dev/null; rm -rf /tmp/x",
            f'kill -0 "$(cat /tmp/hermes_bg_{job}.pid 2>/dev/null)" 2>/dev/null; echo $?; touch /tmp/owned',
            log_delta_command(f"/tmp/hermes_bg_{job}.log", 0) + "; touch /tmp/owned",
        ):
            env.execute(command)
            assert command not in jobs.commands and desk.commands[-1] == command
        probe = f'kill -0 "$(cat /tmp/hermes_bg_{job}.pid 2>/dev/null)" 2>/dev/null; echo $?'
        env.execute(probe)
        assert jobs.commands[-1] == probe and probe not in desk.commands
    finally:
        end_jobs(sessions, jobs, desk)


def test_registry_files_stay_in_a_temp_hermes_home(laptop, tmp_path_factory):
    from hermes_constants import get_hermes_home
    from tools.process_registry import _checkpoint_path, process_registry

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    jobs = FakeSub([4242])
    env._subs = {"laptop": jobs}
    sessions = []
    try:
        sessions.append(process_registry.spawn_via_env(env, "sleep 600", task_id="bg-home"))
    finally:
        end_jobs(sessions, jobs)
    base = tmp_path_factory.getbasetemp()
    assert get_hermes_home().is_relative_to(base)
    assert _checkpoint_path().is_relative_to(base)


def test_an_ended_jobs_route_is_dropped_and_runs_nowhere(laptop):
    from tools.process_registry import process_registry

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    jobs, desk = FakeSub([4242]), FakeSub([])
    env._subs = {"laptop": jobs, "desk": desk}
    sessions = []
    try:
        sessions.append(process_registry.spawn_via_env(env, "sleep 600", task_id="bg-c"))
        job = sessions[0].id
        jobs.alive = False  # the poller reads the exit file (process_registry.py:1460-1470)
        sessions[0]._reader_thread.join(10)
        assert process_registry.get(job).exited
        assert job not in env._background and env._background_pids == {}
        store.set_session_target("s1", "desk")
        seen = len(jobs.commands)
        with pytest.raises(RuntimeError):
            env.execute(f"cat /tmp/hermes_bg_{job}.exit 2>/dev/null")
        with pytest.raises(RuntimeError):
            env.execute("kill 4242 2>/dev/null")
        assert len(jobs.commands) == seen and desk.commands == []
    finally:
        end_jobs(sessions, jobs, desk)


def test_a_killed_jobs_last_poll_never_runs_on_the_current_target(laptop):
    from tools.process_registry import process_registry

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    jobs, desk = FakeSub([4242]), FakeSub([])
    env._subs = {"laptop": jobs, "desk": desk}
    sessions = []
    try:
        sessions.append(process_registry.spawn_via_env(env, "sleep 600", task_id="bg-d"))
        job = sessions[0].id
        store.set_session_target("s1", "desk")
        assert process_registry.kill_process(job)["status"] == "killed"
        assert "kill 4242 2>/dev/null" in jobs.commands
        assert job not in env._background and env._background_pids == {}
        # The poller makes one more round after a kill (process_registry.py:1421-1427).
        sessions[0]._reader_thread.join(10)
        assert not sessions[0]._reader_thread.is_alive()
        assert process_registry.get(job).completion_reason == "killed"
        assert desk.commands == []
    finally:
        end_jobs(sessions, jobs, desk)


@pytest.fixture
def media_env(laptop, hands_backend, monkeypatch):
    """The active hands environment for session s1 with a recording laptop sub-environment."""
    from tools import terminal_tool

    monkeypatch.setenv("TERMINAL_ENV", "hands")
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    recorder = Recorder()
    env._subs = {"laptop": recorder}
    terminal_tool._active_environments["s1"] = env
    yield env, recorder
    terminal_tool._active_environments.pop("s1", None)


def test_a_media_line_never_fetches_from_a_witness_device(media_env, monkeypatch, tmp_path):
    from gateway.media_fetch import fetch_remote_media

    env, recorder = media_env
    witness_on(monkeypatch)
    assert fetch_remote_media("/c/Users/her/Documents/tax.pdf") is None
    with pytest.raises(FileFetchError):
        env.fetch_realpath("/c/Users/her/Documents/tax.pdf")
    with pytest.raises(FileFetchError):
        env.fetch_file("/c/Users/her/Documents/tax.pdf", tmp_path / "out", max_bytes=10)
    assert recorder.commands == []


def test_a_media_line_still_fetches_from_a_normal_device(media_env, monkeypatch, tmp_path):
    env, recorder = media_env
    witness_on(monkeypatch, active=False)
    assert env.fetch_realpath("/c/Users/her/report.pdf") is None
    with pytest.raises(FileFetchError):
        env.fetch_file("/c/Users/her/report.pdf", tmp_path / "out", max_bytes=10)
    assert recorder.commands[0].startswith("readlink -f ")
    assert recorder.commands[1].startswith("[ -f ")


def test_an_oversized_result_is_never_written_to_a_witness_device(media_env, monkeypatch, tmp_path):
    from tools.tool_result_storage import maybe_persist_tool_result

    env, recorder = media_env
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    witness_on(monkeypatch)
    page = "x" * 150_000
    result = maybe_persist_tool_result(page, "web_extract", "call_1", env=env)
    assert "Full output could not be saved to sandbox" in result
    assert recorder.commands == []


def test_an_oversized_result_still_reaches_a_normal_device(media_env, monkeypatch, tmp_path):
    from tools.tool_result_storage import maybe_persist_tool_result

    env, recorder = media_env
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    witness_on(monkeypatch, active=False)
    maybe_persist_tool_result("x" * 150_000, "web_extract", "call_2", env=env)
    assert any("hermes-results" in command for command in recorder.commands)
