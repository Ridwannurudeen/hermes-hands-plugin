"""Contract tests against real Hermes core (``BaseEnvironment``, ``LocalEnvironment``, the session
ContextVar): the device side is a fake agent that runs each job with a local bash, through a real
Relay and the loopback client. Skipped when Hermes is not importable."""

import base64
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("tools.environments.base")
pytest.importorskip("gateway.session_context")
pytest.importorskip("agent.terminal_env_provider")

from hands import environment, messages, relay, store  # noqa: E402
from hands.environment import DeviceEnvironment, HandsEnvironment, device_path  # noqa: E402
from hands.provider import HandsProvider  # noqa: E402
from hands_fakes import Agent, Device, hands_db, wired  # noqa: E402,F401  (fixtures)

GIT_BASH = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
BASH = str(GIT_BASH) if os.name == "nt" else shutil.which("bash")
pytestmark = pytest.mark.skipif(not BASH or not Path(BASH).exists(), reason="needs bash")
windows_device = pytest.mark.skipif(
    os.name != "nt", reason="the fake device runs this host's bash, so only here is it Windows"
)

release = threading.Event()


def bash_job(job):
    """What the device agent does with an exec job, marked so device output is recognisable."""
    if "sleep 99" in job["script"]:
        release.wait(10)
        return "", 0
    args = [BASH, *(["-l"] if job["login"] else []), "-c", job["script"]]
    env = {**os.environ, "HANDS_FAKE_DEVICE": "device"}
    stdin = job.get("stdin")
    feed = {"stdin": subprocess.DEVNULL} if stdin is None else {"input": stdin.encode("utf-8")}
    # A file, not a pipe: a job that backgrounds a process (core's launcher) returns when bash does.
    with tempfile.TemporaryFile() as output:
        done = subprocess.run(
            args,
            stdout=output,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=60,
            **feed,
        )
        output.seek(0)
        return output.read().decode("utf-8", "replace"), done.returncode


class Ctx:
    def __init__(self):
        self.cron = None
        self.config = {}

    def current_cron_execution(self):
        return self.cron

    def get_config(self, key, default=None):
        return self.config.get(key, default)


def run_terminal(env, command, *, workdir=None):
    """A foreground terminal call as core makes it: the cwd it picks (terminal_tool.py:1365-1376)
    and the record it keeps afterwards (terminal_tool_result.py:222-225)."""
    from tools import terminal_tool

    cwd = terminal_tool._resolve_command_cwd(
        workdir=workdir, default_cwd="~", session_key="s1", env_type="hands", env=env
    )
    result = env.execute(command, cwd=cwd, bounded_capture=True)
    if not workdir and result.get("cwd_observed"):
        terminal_tool.record_session_cwd("s1", result["cwd"])
    return result


@pytest.fixture(autouse=True)
def fresh_session_cwds():
    """Each test is its own process as far as the per-container cwd memory goes."""
    environment._SESSION_CWDS.clear()
    yield
    environment._SESSION_CWDS.clear()


@pytest.fixture
def laptop(wired, tmp_path, monkeypatch):
    """A paired 'laptop' whose home is a temp dir, chosen by session s1; yields ``(hub, device, home)``."""
    from tools import terminal_tool

    hub, _ = wired
    home = tmp_path / "dev home"
    home.mkdir()
    server = tmp_path / "srv"
    server.mkdir()
    monkeypatch.setenv("MESSAGING_CWD", str(server))
    monkeypatch.setenv("HERMES_SESSION_KEY", "s1")
    device = Device(home=str(home), device_os="Windows-11" if os.name == "nt" else "Linux")
    store.set_session_target("s1", "laptop")
    terminal_tool.clear_session_cwd("s1")
    release.clear()
    yield hub, device, home
    release.set()
    terminal_tool.clear_session_cwd("s1")


@pytest.fixture
def hands_backend():
    """``terminal.backend: hands`` registered in core, as the plugin's register() does."""
    from agent import terminal_env_registry

    provider = HandsProvider(Ctx())
    previous = terminal_env_registry.snapshot_registration("hands")
    terminal_env_registry.register_provider(provider)
    yield provider
    terminal_env_registry.restore_registration("hands", provider, previous)


class FakeHandle:
    """Stands in for RemoteProcessHandle: records each job and answers it at once with no output."""

    jobs: list[dict] = []

    def __init__(self, device, script, *, login, timeout, inline_limit=None, stdin=None, file_op=False):
        FakeHandle.jobs.append(
            {"script": script, "stdin": stdin, "file_op": file_op, "login": login}
        )
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        self.stdout = os.fdopen(read_fd, "r", encoding="utf-8-sig")
        self.returncode = 0

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


@pytest.fixture
def fake_jobs(monkeypatch):
    FakeHandle.jobs = []
    monkeypatch.setattr(environment, "RemoteProcessHandle", FakeHandle)
    return FakeHandle.jobs


def device_env(home="/c/Users/r b", *, windows=False):
    return DeviceEnvironment(
        "laptop", cwd="~", timeout=5, home=home, windows=windows, inline_limit=8192
    )


def test_provider_flags():
    provider = HandsProvider(Ctx())
    assert (provider.name, provider.display_name) == ("hands", "Hermes Hands")
    assert provider.is_remote and provider.is_container and not provider.supports_streams
    assert provider.skip_container_guards is False
    assert provider.default_cwd == "~"
    assert provider.cache_path_base is None
    assert provider.strip_env_keys == frozenset({"HANDS_RELAY_SEED"})
    assert provider.is_available() and provider.check_requirements({})


def test_device_path():
    assert device_path("C:\\Users\\me\\a b") == "/c/Users/me/a b"
    assert device_path("d:/x") == "/d/x"
    assert device_path("/home/me") == "/home/me"


def test_terminal_and_cd_on_the_device(laptop):
    hub, device, home = laptop
    with Agent(hub, device, bash_job) as agent:
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        assert env.cwd == device_path(str(home))  # absolute before core stamps the sandbox home
        first = env.execute("echo $HANDS_FAKE_DEVICE", bounded_capture=True)
        assert first["returncode"] == 0
        note, output = first["output"].split("\n", 1)
        assert note.startswith("hands: now on laptop (") and output.strip() == "device"
        assert agent.jobs[0]["login"] is True  # init_session's bootstrap ran on first use
        assert env._subs["laptop"]._snapshot_ready  # the login snapshot works under this bash
        assert run_terminal(env, "mkdir -p sub && cd sub")["returncode"] == 0
        again = run_terminal(env, "pwd")
        assert again["output"].strip().endswith("/sub") and "hands:" not in again["output"]
        # Only a terminal command moves the cwd (core records only those): not a file tool's own cd.
        assert env.execute("cd ..")["returncode"] == 0
        assert run_terminal(env, "pwd")["output"].strip().endswith("/sub")


def test_stdin_travels_beside_the_script_byte_exact(laptop):
    hub, device, home = laptop
    with Agent(hub, device, bash_job) as agent:
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        for name, content in (
            ("a.txt", "one\ntwo"),
            ("b.txt", "one\ntwo\n"),
            ("c.txt", "naïve ✓ run sudo apt install, then pool.shutdown()\n"),
        ):
            result = env.execute(f"cat > '{name}'", stdin_data=content)
            assert result["returncode"] == 0, result
            assert (home / name).read_bytes() == content.encode("utf-8")
    writes = [job for job in agent.jobs if job.get("stdin")]
    assert len(writes) == 3
    assert not any(
        "HERMES_STDIN_" in job["script"] or "sudo" in job["script"] for job in agent.jobs
    )


def test_device_hands_stdin_to_the_handle_not_the_script(wired, fake_jobs):
    env = device_env()
    result = env.execute("cat > 'notes.md'", stdin_data="To install, run sudo apt install rg.\n")
    assert result["returncode"] == 0
    write = fake_jobs[-1]
    assert write["stdin"] == "To install, run sudo apt install rg.\n"
    assert "HERMES_STDIN_" not in write["script"] and "apt install" not in write["script"]


def test_the_gateway_sudo_password_never_reaches_a_device(wired, fake_jobs, monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "gateway-root-secret")
    env = device_env()
    env.execute("sudo -n true 2>/dev/null; echo done")
    for job in fake_jobs:
        assert "gateway-root-secret" not in job["script"] and job["stdin"] is None
    assert "sudo -S" not in fake_jobs[-1]["script"]


def test_offline_at_first_use_then_recovery(laptop, monkeypatch):
    hub, device, home = laptop
    monkeypatch.setattr(store, "OFFLINE_AFTER", -1)
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    started = time.monotonic()
    result = env.execute("echo hi", bounded_capture=True)
    assert time.monotonic() - started < 5
    assert (
        result["returncode"] == relay.UNREACHABLE and messages.offline("laptop") in result["output"]
    )
    monkeypatch.setattr(store, "OFFLINE_AFTER", 20)
    with Agent(hub, device, bash_job) as agent:
        assert env.execute("echo $HANDS_FAKE_DEVICE")["output"].strip() == "device"
        assert agent.jobs[0]["login"] is True  # the bootstrap is retried after an offline init


def test_offline_after_success_keeps_cwd(laptop, monkeypatch):
    hub, device, home = laptop
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    with Agent(hub, device, bash_job):
        run_terminal(env, "mkdir -p kept && cd kept")
    monkeypatch.setattr(store, "OFFLINE_AFTER", -1)
    offline = run_terminal(env, "pwd")
    assert offline["returncode"] == relay.UNREACHABLE and "offline" in offline["output"]
    monkeypatch.setattr(store, "OFFLINE_AFTER", 20)
    with Agent(hub, device, bash_job):
        assert run_terminal(env, "pwd")["output"].strip().endswith("/kept")


def test_timeout_is_cores_124_and_cancels_the_job(laptop):
    hub, device, home = laptop
    with Agent(hub, device, bash_job) as agent:
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        env.execute("true")
        result = env.execute("sleep 99", timeout=1)
        assert result["returncode"] == 124 and result.get("hermes_timed_out") is True
        deadline = time.monotonic() + 5
        while not any(job["type"] == "cancel" for job in agent.jobs):
            release.set()  # let the fake agent finish so it can poll the cancel
            assert time.monotonic() < deadline, "no cancel reached the device"
            time.sleep(0.02)


def test_switch_to_server_keeps_each_targets_cwd(laptop, tmp_path):
    hub, device, home = laptop
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        run_terminal(env, "mkdir -p deep && cd deep")
        store.set_session_target("s1", "server")
        on_server = run_terminal(env, "echo ${HANDS_FAKE_DEVICE:-server}; pwd")
        lines = on_server["output"].splitlines()
        assert lines[0] == messages.TARGET_NOTE_SERVER and lines[1] == "server"
        assert lines[2].rstrip("/").endswith("srv")
        assert env.is_local is True and env.uses_host_filesystem is True
        store.set_session_target("s1", "laptop")
        back = run_terminal(env, "pwd")
        assert back["output"].strip().endswith("/deep")
        assert env.is_local is False and env.uses_host_filesystem is False
        env.cleanup()


def test_switch_across_new_objects_ignores_the_other_targets_cwd(laptop):
    """A session outlives its backend object (idle reaper, gateway restart): the next object must not
    reuse the other target's recorded cwd, and notes its target on its first terminal command."""
    hub, device, home = laptop
    with Agent(hub, device, bash_job):
        first = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        run_terminal(first, "mkdir -p deep && cd deep")
        first.cleanup()
        store.set_session_target("s1", "server")
        second = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        on_server = run_terminal(second, "pwd")
        note, where = on_server["output"].splitlines()[:2]
        assert note == messages.TARGET_NOTE_SERVER and where.rstrip("/").endswith("srv")
        assert "hands:" not in run_terminal(second, "pwd")["output"]
        second.cleanup()
        third = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        assert run_terminal(third, "pwd")["output"].startswith(messages.TARGET_NOTE_SERVER)
        third.cleanup()


def test_a_file_tool_after_a_switch_keeps_the_servers_cwd_off_the_device(laptop):
    """Only terminal commands count as having run on a target: core records the cwd from those alone."""
    from tools import terminal_tool

    hub, device, home = laptop
    with Agent(hub, device, bash_job):
        store.set_session_target("s1", "server")
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        run_terminal(env, "true")
        terminal_tool.record_session_cwd("s1", "/opt/srvapp")  # where the server session cd'd
        store.set_session_target("s1", "laptop")  # /hands use laptop
        env.execute("cat notes.txt 2>/dev/null; true", cwd=env.cwd)  # read_file runs first
        # It saw the switch and moved core's record to the laptop (terminal_tool.py:266-276).
        assert store.get_last_run("s1") == "laptop"
        first = run_terminal(env, "pwd")
        assert first["returncode"] == 0 and first["cwd"] == device_path(str(home)), first
        assert store.get_last_run("s1") == "laptop"
        assert run_terminal(env, "cd ~ && pwd")["returncode"] == 0


def test_a_workdir_runs_where_it_says_after_a_switch(laptop):
    hub, device, home = laptop
    (home / "proj").mkdir()
    with Agent(hub, device, bash_job):
        store.set_session_target("s1", "server")
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        run_terminal(env, "true")
        store.set_session_target("s1", "laptop")
        there = run_terminal(env, "pwd", workdir=f"{device_path(str(home))}/proj")
        assert there["cwd"] == f"{device_path(str(home))}/proj"


def test_a_device_starts_in_its_home_whatever_the_gateway_cwd(laptop, tmp_path, monkeypatch):
    """The fake device is this machine, so the gateway directory exists there: only the target
    decides where the command starts."""
    hub, device, home = laptop
    configured = tmp_path / "gateway project"  # terminal.cwd on the gateway
    configured.mkdir()
    monkeypatch.setenv("TERMINAL_CWD", str(configured))
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd=str(configured), timeout=30)
        assert env.cwd == device_path(str(home))
        # core's default when the session has no record (terminal_tool.py:1061)
        first = env.execute("pwd", cwd=str(configured), bounded_capture=True)
        assert first["returncode"] == 0 and first["cwd"] == device_path(str(home)), first
        env.cwd = str(tmp_path)  # a Desktop or ACP workspace override (terminal_tool.py:358-362)
        assert env.cwd == device_path(str(home))
        store.set_session_target("s1", "server")
        assert Path(env.cwd) == tmp_path  # the workspace is where the server starts now
        env.cwd = str(tmp_path)
        assert env._subs["server"].cwd == str(tmp_path)


def test_the_server_keeps_the_session_cwd_after_a_workdir_command(laptop):
    """Core drops a /home or /Users record outside the sandbox home and passes "~" (terminal_tool.py:
    1041-1059); on the server that home is the live cwd, which the workdir command moved."""
    hub, device, home = laptop
    store.set_session_target("s1", "server")
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    run_terminal(env, "mkdir -p proj other && cd proj")
    elsewhere = env.execute(
        "pwd", cwd=str(Path(os.environ["MESSAGING_CWD"]) / "other"), bounded_capture=True
    )
    assert elsewhere["output"].strip().rstrip("/").endswith("other")
    after = env.execute("pwd", cwd="~", bounded_capture=True)
    assert after["output"].strip().rstrip("/").endswith("proj"), after


def last_line(result):
    return result["output"].strip().splitlines()[-1]


def test_a_first_command_that_prints_no_cwd_keeps_the_other_targets_cwd_away(laptop, monkeypatch):
    """Core records the cwd only from a command that printed where it ended: offline, refused or
    exited early, the first command on the new target leaves the old target's record in place."""
    from tools import terminal_tool

    hub, device, home = laptop
    store.set_session_target("s1", "server")
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    run_terminal(env, "true")
    terminal_tool.record_session_cwd("s1", "/opt/srvapp")
    store.set_session_target("s1", "laptop")
    monkeypatch.setattr(store, "OFFLINE_AFTER", -1)
    assert run_terminal(env, "pwd")["returncode"] == relay.UNREACHABLE
    monkeypatch.setattr(store, "OFFLINE_AFTER", 20)
    with Agent(hub, device, bash_job):
        assert run_terminal(env, "exit 3")["returncode"] == 3
        assert run_terminal(env, "pwd", workdir=device_path(str(home)))["returncode"] == 0
        first = run_terminal(env, "pwd")
        assert first["returncode"] == 0 and first["cwd"] == device_path(str(home)), first
        run_terminal(env, "mkdir -p proj && cd proj")
        store.set_session_target("s1", "server")
        assert run_terminal(env, "exit 3")["returncode"] == 3
        assert last_line(run_terminal(env, "pwd")).rstrip("/").endswith("srv")


def test_a_workspace_override_never_becomes_the_device_cwd(laptop):
    """A TUI, ACP or Desktop workspace is recorded as the session's cwd (terminal_tool.py:350-362)."""
    from tools import terminal_tool

    hub, device, home = laptop
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        terminal_tool._active_environments["s1"] = env
        try:
            run_terminal(env, "true")
            terminal_tool.register_task_env_overrides("s1", {"cwd": "/srv/workspace"})
            first = run_terminal(env, "pwd")
            assert first["returncode"] == 0 and first["cwd"] == device_path(str(home)), first
            terminal_tool.register_task_env_overrides("s1", {"cwd": "/srv/workspace"})
            fresh = HandsEnvironment(Ctx(), cwd="/srv/workspace", timeout=30)  # after a restart
            again = run_terminal(fresh, "pwd")
            assert again["returncode"] == 0 and again["cwd"] == device_path(str(home)), again
        finally:
            terminal_tool._active_environments.pop("s1", None)
            terminal_tool.clear_task_env_overrides("s1")


def test_a_workdir_never_moves_where_the_next_command_starts(laptop, monkeypatch):
    """Without a session key core keys the record by task id (terminal_tool.py:1530); a workdir
    command, which core never records, is the session's first or a later one."""
    from tools import terminal_tool

    hub, device, home = laptop
    store.set_session_target("s1", "server")
    srv = Path(os.environ["MESSAGING_CWD"])
    (srv / "other").mkdir()
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    env.execute("pwd", cwd=str(srv / "other"), bounded_capture=True)  # workdir= first
    assert last_line(env.execute("pwd", cwd="~", bounded_capture=True)).rstrip("/").endswith("srv")
    monkeypatch.delenv("HERMES_SESSION_KEY")
    cli = HandsEnvironment(Ctx(), cwd="~", timeout=30)

    def run(command, workdir=None):
        cwd = terminal_tool._resolve_command_cwd(
            workdir=workdir, default_cwd="~", session_key="default", env_type="hands", env=cli
        )
        result = cli.execute(command, cwd=cwd, bounded_capture=True)
        if not workdir and result.get("cwd_observed"):
            terminal_tool.record_session_cwd("default", result["cwd"])
        return result

    try:
        run("mkdir -p proj && cd proj")
        run("pwd", workdir=str(srv / "other"))
        assert last_line(run("pwd")).rstrip("/").endswith("proj")
    finally:
        terminal_tool.clear_session_cwd("default")


def test_execute_code_never_moves_the_terminal_cwd(laptop):
    """execute_code runs on the same environment from "/" (code_kernel_remote.py:98-101)."""
    from tools import code_kernel_remote

    hub, device, home = laptop
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        assert run_terminal(env, "pwd")["cwd"] == device_path(str(home))
        assert code_kernel_remote._sh(env, "pwd").strip().endswith("/")
        assert run_terminal(env, "pwd")["cwd"] == device_path(str(home))
        assert env.cwd == device_path(str(home))


def test_a_workdir_equal_to_the_creation_cwd_is_honoured_on_a_device(laptop):
    hub, device, home = laptop
    proj = f"{device_path(str(home))}/proj"
    (home / "proj" / "sub").mkdir(parents=True)
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd=proj, timeout=30)  # the record core recreated it with
        run_terminal(env, "cd proj/sub")
        assert run_terminal(env, "pwd", workdir=proj)["cwd"] == proj


def test_a_new_conversation_in_the_same_chat_gets_the_note(laptop, monkeypatch):
    """/new keeps the session key, so core hands the fresh conversation the same object."""
    hub, device, home = laptop
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        monkeypatch.setenv("HERMES_SESSION_ID", "first")
        assert run_terminal(env, "true")["output"].startswith("hands: now on laptop")
        assert "hands:" not in run_terminal(env, "true")["output"]
        monkeypatch.setenv("HERMES_SESSION_ID", "second")
        assert run_terminal(env, "true")["output"].startswith("hands: now on laptop")


def test_backend_survives_core_per_turn_teardown(laptop):
    from tools import terminal_tool
    from tools.terminal_tool_lifecycle import is_persistent_env

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    terminal_tool._active_environments["hands-test"] = env
    try:
        assert HandsEnvironment._persistent is True and is_persistent_env("hands-test") is True
    finally:
        terminal_tool._active_environments.pop("hands-test", None)


def test_sandbox_home_follows_the_target(laptop):
    from tools.terminal_tool_config import plugin_sandbox_home

    hub, device, home = laptop
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    env._hermes_sandbox_home = "/stamped/by/core/once"  # what terminal_tool_backends.py:231 does
    assert env._hermes_sandbox_home == device_path(str(home))
    if os.name != "nt":
        assert plugin_sandbox_home(env) == str(home)
    store.set_session_target("s1", "server")
    assert env._hermes_sandbox_home == env.cwd
    assert env._hermes_sandbox_home.rstrip("/\\").endswith("srv")
    store.set_session_target("s1", "ghost")
    assert env._hermes_sandbox_home is None and plugin_sandbox_home(env) is None


def test_store_failure_never_raises_into_core_and_runs_nothing(laptop, monkeypatch, caplog):
    import sqlite3

    from tools.file_operations import ShellFileOperations

    hub, device, home = laptop

    def broken(session_key):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "get_session_target", broken)
    caplog.set_level("WARNING", logger="hands.environment")
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)  # create_environment must not raise
    server_cwd = env.cwd
    assert server_cwd.rstrip("/\\").endswith("srv") and isinstance(env.env, dict)
    # False, so read_file and search_files go through execute() (file_operations.py:912-922)
    assert env.is_local is False and env.uses_host_filesystem is False
    assert caplog.text.count("device store is unreadable") == 1  # logged once
    marker = Path(server_cwd) / "ran"
    result = env.execute("echo x > ran", bounded_capture=True)
    assert result == {"output": messages.STORE_DOWN, "returncode": relay.UNREACHABLE}
    assert not marker.exists()
    secret = Path(server_cwd) / "gateway.txt"
    secret.write_text("gateway-only\n", encoding="utf-8")
    read = ShellFileOperations(env).read_file(str(secret))
    assert "gateway-only" not in json.dumps(read.to_dict()) and read.error
    with pytest.raises(sqlite3.Error):
        env.fetch_realpath(
            "/etc/hostname"
        )  # a media fetch catches it (gateway/media_fetch.py:112-114)
    assert caplog.text.count("device store is unreadable") == 1


def test_cron_runs_on_the_server(laptop):
    ctx = Ctx()
    ctx.cron = object()
    env = HandsEnvironment(ctx, cwd="~", timeout=30)
    assert env.execute("echo ${HANDS_FAKE_DEVICE:-server}")["output"].strip() == "server"


def test_witness_uses_environment_owner_target_not_tool_target_arguments(laptop, monkeypatch):
    from hands import witness

    ctx = Ctx()
    store.set_session_target("s1", "laptop", "telegram:42")
    monkeypatch.setattr(
        store, "get_device", lambda name: {"name": name, "device_id": "device-id"}
    )

    def device_by_id(device_id):
        assert device_id == "device-id"
        return {
            "name": "laptop",
            "witness": True,
            "session_state": "active",
            "capabilities": ["witness-v1"],
        }

    monkeypatch.setattr(store, "device_by_id", device_by_id)
    caller = ["telegram:7"]
    monkeypatch.setattr(environment.targets, "current_caller", lambda: caller[0])

    guest = witness.pre_tool_call(
        ctx,
        "terminal",
        {"command": "rm -rf /tmp/hands-test", "target": "laptop"},
    )
    assert guest is None

    caller[0] = "telegram:42"
    owner = witness.pre_tool_call(
        ctx,
        "terminal",
        {"command": "rm -rf /tmp/hands-test", "target": "server"},
    )
    assert owner["action"] == "approve"


def test_witness_target_resolver_exception_blocks_protected_action(laptop, monkeypatch):
    from hands import witness

    def fail(ctx):
        raise RuntimeError("target resolver failed")

    monkeypatch.setattr(environment, "resolve_current_target", fail)

    result = witness.pre_tool_call(Ctx(), "terminal", {"command": "pwd"})

    assert result["action"] == "block"


def test_the_relay_seed_never_reaches_a_server_command(laptop, hands_backend, monkeypatch):
    monkeypatch.setenv("HANDS_RELAY_SEED", "ab" * 32)
    store.set_session_target("s1", "server")
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    output = env.execute('echo "[${HANDS_RELAY_SEED:-unset}]"', bounded_capture=True)["output"]
    assert "[unset]" in output and "ab" * 32 not in output


def test_unknown_device_fails_closed(wired, monkeypatch):
    monkeypatch.setenv("HERMES_SESSION_KEY", "s2")
    store.set_session_target("s2", "ghost")
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    assert env.cwd == "~"
    result = env.execute("echo hi")
    assert result["returncode"] == relay.UNREACHABLE
    assert messages.unknown_device("ghost") in result["output"]


def x_runs(output: str) -> int:
    return sum(len(run) for run in re.findall(r"x{100,}", output))


def test_inline_output_limit_applies_to_terminal_calls_only(laptop):
    hub, device, home = laptop
    ctx = Ctx()
    ctx.config["inline_output_limit_bytes"] = 8192
    command = "printf '%40000s' '' | tr ' ' x"
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(ctx, cwd="~", timeout=30)
        terminal = env.execute(command, bounded_capture=True)
        assert "bytes of output omitted here (inline_output_limit_bytes)" in terminal["output"]
        assert 4000 < x_runs(terminal["output"]) <= 8192
        assert terminal["cwd"] == device_path(str(home))  # core's cwd marker survived in the tail
        assert x_runs(env.execute(command)["output"]) == 40000  # file reads keep every byte


def test_gateway_home_maps_only_a_file_tools_path_words(wired, monkeypatch):
    monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
    env = device_env()
    assert env._file_command("cat '/home/gw/a b.txt'") == "cat '/c/Users/r b/a b.txt'"
    assert env._file_command("cat '/home/gw'") == "cat '/c/Users/r b'"
    assert env._file_command("cd /home/gw && ls") == "cd '/c/Users/r b' && ls"
    for untouched in (
        "cat '/home/gwx/a'",
        "cat '/srv/home/gw/a'",
        "cat 'x/home/gw/a'",
        "echo '~/home/gw'",
    ):
        assert env._file_command(untouched) == untouched
    assert device_env("/home/gw")._file_command("cat '/home/gw/a'") == "cat '/home/gw/a'"
    quoted = device_env("/c/Users/O'Brien")._file_command("cat '/home/gw/notes.txt' 2>/dev/null")
    assert shlex.split(quoted) == ["cat", "/c/Users/O'Brien/notes.txt", "2>/dev/null"]


def test_gateway_home_never_rewrites_a_terminal_or_background_command(laptop, monkeypatch):
    hub, device, home = laptop
    monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
    with Agent(hub, device, bash_job) as agent:
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        shown = env.execute("echo /home/gw/build '/home/gw/x'", bounded_capture=True)
        assert shown["output"].splitlines()[-1] == "/home/gw/build /home/gw/x"
        # what core's launcher and poller send: they name a job file (process_registry.py:1282-1288)
        env._subs["laptop"].execute("echo '/home/gw/bg' # hermes_bg_t1.log")
    assert any("/home/gw/bg" in job.get("script", "") for job in agent.jobs)


def test_a_gateway_home_path_from_the_file_tools_lands_in_the_device_home(laptop, monkeypatch):
    from tools.file_operations import ShellFileOperations

    hub, device, home = laptop
    monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        written = ShellFileOperations(env).write_file("/home/gw/mapped notes.txt", "mapped\n")
        assert written.error is None and written.verified is True, written.to_dict()
    assert (home / "mapped notes.txt").read_bytes() == b"mapped\n"


class Capture:
    """A terminal backend that records what core's ShellFileOperations sends and answers success."""

    cwd = "/"

    def __init__(self):
        self.commands = []

    def execute(self, command, cwd="", **kwargs):
        self.commands.append(command)
        answers = {"test -e ": "exists", "command -v grep ": "yes"}  # rg missing: core's grep lane
        output = next((out for start, out in answers.items() if command.startswith(start)), "")
        return {"output": output, "returncode": 0}


def snippet_program(command: str) -> str:
    encoded = re.search(r"b64decode\('([A-Za-z0-9+/=]*)'\)", command).group(1)
    return base64.b64decode(encoded).decode("utf-8")


def test_core_python_snippet_paths_reach_the_device_as_it_names_them(wired, monkeypatch):
    from tools.file_operations import ShellFileOperations

    capture = Capture()
    ShellFileOperations(capture).delete_file("/c/Users/r b/O'Brien.txt")
    [delete] = capture.commands
    windows = device_env(windows=True)._file_command(delete)
    assert 'pathlib.Path(__import__("sys").argv[1])' in snippet_program(windows)
    assert windows.endswith(" \"$(cygpath -m '/c/Users/r b/O'\"'\"'Brien.txt')\"")
    assert device_env()._file_command(delete) == delete  # bash and POSIX Python agree on the path
    monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
    capture.commands.clear()
    ShellFileOperations(capture).delete_file("/home/gw/old.txt")
    linux = device_env("/home/alice")._file_command(capture.commands[0])
    assert 'pathlib.Path("/home/alice/old.txt")' in snippet_program(linux)
    assert linux.startswith('python3 -c "import base64; exec(base64.b64decode(')


def test_a_windows_path_core_joined_onto_the_base_becomes_the_drive_path(wired):
    windows = device_env("/c/Users/dev", windows=True)
    for joined in ("/c/Users/dev/C:\\Users\\me\\n.txt", "/c/Users/dev/C:/Users/me/n.txt"):
        assert windows._file_path(joined) == "/c/Users/me/n.txt"
        assert device_env("/c/Users/dev")._file_path(joined) == joined  # only Windows devices
    assert windows._file_path("/c/Users/dev/a:b.txt") == "/c/Users/dev/a:b.txt"
    assert windows._file_path("file:///C:/Users") == "file:///C:/Users"  # not joined onto a base
    # joined onto a gateway terminal.cwd (file_tools_paths.py:106-112, 144)
    assert windows._file_path("/srv/gw proj/C:\\Users\\me\\n.txt") == "/c/Users/me/n.txt"


def test_search_patterns_reach_the_device_as_given(wired, monkeypatch):
    """Core quotes a pattern like a path (file_operations_search.py:1360, 1379); the search path is
    the model's own, never expanded on the gateway (file_tools.py:1102)."""
    from tools.file_operations import ShellFileOperations

    monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
    capture = Capture()
    for pattern in ("/home/gw/.cache", "file:///C:/Users"):
        ShellFileOperations(capture).search(pattern=pattern, path="/c/Users/dev", target="content")
    searches = [c for c in capture.commands if "/home/gw/.cache" in c or "file:///C:/" in c]
    assert any("/home/gw/.cache" in c for c in searches) and any("file:///" in c for c in searches)
    for device in (device_env("/c/Users/dev", windows=True), device_env("/home/alice")):
        for command in searches:
            assert device._file_command(command) == command


def test_an_unquoted_gateway_home_path_maps_too(wired, monkeypatch):
    """shlex.quote leaves a safe path bare, as image_source.py:279 sends it."""
    monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
    command = "head -c 52428801 < /home/gw/shot.png | base64 | tr -d '\\n'"
    mapped = device_env("/c/Users/r b")._file_command(command)
    assert mapped == "head -c 52428801 < '/c/Users/r b/shot.png' | base64 | tr -d '\\n'"
    assert device_env()._file_command("cat /home/gwx/a /srv/home/gw/a") == (
        "cat /home/gwx/a /srv/home/gw/a"
    )


def linux_atomic_write(home: str, windows_path: str) -> str:
    """Core's atomic write of ``windows_path`` as a Linux gateway builds it: joined onto the base,
    backslashes kept (local.py:186) and the parent taken with posixpath (file_operations.py:587)."""
    from tools.file_operations import ShellFileOperations

    capture = Capture()
    ShellFileOperations(capture)._atomic_write("/placeholder/n.txt", "x")
    joined = f"{home}/{windows_path}"
    return (
        capture.commands[-1]
        .replace("d='/placeholder'", f"d={shlex.quote(posixpath.dirname(joined))}")
        .replace("t='/placeholder/n.txt'", f"t={shlex.quote(joined)}")
    )


def test_a_windows_path_write_from_a_linux_gateway_gets_its_real_parent(wired):
    script = linux_atomic_write("/c/Users/dev", "C:\\Users\\me\\new\\n.txt")
    assert "d=/c/Users/dev; t='/c/Users/dev/C:\\Users\\me\\new\\n.txt'; " in script
    mapped = device_env("/c/Users/dev", windows=True)._file_command(script)
    assert "d=/c/Users/me/new; t=/c/Users/me/new/n.txt; " in mapped


@windows_device
def test_a_windows_path_write_into_a_new_folder_lands(laptop, tmp_path):
    hub, device, home = laptop
    target = tmp_path / "elsewhere" / "new folder" / "n.txt"
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        script = linux_atomic_write(device_path(str(home)), str(target))
        result = env.execute(script, stdin_data="landed\n")
        assert result["returncode"] == 0, result
    assert target.read_bytes() == b"landed\n" and list(home.iterdir()) == []


@windows_device
def test_delete_on_a_windows_device_deletes_the_file(file_tools_on_laptop):
    from tools.file_operations import ShellFileOperations

    file_tools, home = file_tools_on_laptop
    for name in ("victim.txt", "naïve.txt", "O'Brien.txt"):
        (home / name).write_text("x\n", encoding="utf-8")
        env = file_tools._get_file_ops("t1").env
        result = ShellFileOperations(env).delete_file(f"{device_path(str(home))}/{name}")
        assert result.error is None and not (home / name).exists(), (name, result.to_dict())
    (home / "gone.txt").write_text("x\n", encoding="utf-8")
    patch = f"*** Begin Patch\n*** Delete File: {device_path(str(home))}/gone.txt\n*** End Patch\n"
    deleted = json.loads(file_tools.patch_tool(mode="patch", patch=patch, task_id="t1"))
    assert not deleted.get("error") and not (home / "gone.txt").exists(), deleted


@windows_device
def test_a_windows_form_path_in_write_file_lands_where_it_names(file_tools_on_laptop):
    file_tools, home = file_tools_on_laptop
    result = json.loads(
        file_tools.write_file_tool(str(home / "win notes.txt"), "win\n", task_id="t1")
    )
    assert not result.get("error"), result
    assert (home / "win notes.txt").read_bytes() == b"win\n"
    assert [p.name for p in home.rglob("*")] == ["win notes.txt"]


@pytest.fixture
def file_tools_on_laptop(laptop, hands_backend, tmp_path, monkeypatch):
    """Core's own write_file/patch tools with terminal.backend: hands, the laptop chosen."""
    from tools import file_tools, terminal_tool

    hub, device, home = laptop
    monkeypatch.setenv("TERMINAL_ENV", "hands")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes home"))
    with Agent(hub, device, bash_job):
        yield file_tools, home
    for key, env in list(terminal_tool._active_environments.items()):
        if isinstance(env, HandsEnvironment):
            terminal_tool._active_environments.pop(key, None)
            env.cleanup()
    file_tools.clear_file_ops_cache()


@pytest.mark.parametrize("session_key", ["", "s1"], ids=["cli", "gateway"])
def test_relative_file_tool_paths_follow_the_terminal_cwd(
    file_tools_on_laptop, hands_backend, monkeypatch, session_key
):
    """Core's own tools after a cd, as the live run did: write and patch anchor relative paths on the
    session's cwd record or the sandbox home (file_tools_paths.py:131-144, 276-301), read and search
    pass them to the shell (file_tools.py:685, 1102). On the local backend all of them follow the
    terminal's cwd. Without a session key core records under the task id (terminal_tool.py:1530); in
    the gateway the session key and the file tools' task id differ (run_turn_runner.py:983-987)."""
    from tools.terminal_tool import clear_session_cwd, terminal_tool

    file_tools, home = file_tools_on_laptop
    hands_backend._ctx.config["default_target"] = "laptop"
    if session_key:
        store.set_session_target(session_key, "laptop")
    else:
        monkeypatch.delenv("HERMES_SESSION_KEY")
    task = "live-1"
    clear_session_cwd(task)  # a cwd record a previous test left under this task id
    base = device_path(str(home))
    assert json.loads(terminal_tool("uname -a; pwd", task_id=task))["exit_code"] == 0
    moved = json.loads(
        terminal_tool(f"mkdir -p '{base}/proj' && cd '{base}/proj' && pwd", task_id=task)
    )
    assert moved["output"].strip().endswith("/proj"), moved
    assert json.loads(terminal_tool("pwd", task_id=task))["output"].strip().endswith("/proj")
    written = json.loads(file_tools.write_file_tool("notes/nl.txt", "line one\n", task_id=task))
    assert not written.get("error"), written
    assert (home / "proj" / "notes" / "nl.txt").read_bytes() == b"line one\n"
    read = json.loads(file_tools.read_file_tool("notes/nl.txt", task_id=task))
    assert "line one" in read.get("content", ""), read
    patched = json.loads(
        file_tools.patch_tool(
            mode="replace", path="notes/nl.txt", old_string="one", new_string="two", task_id=task
        )
    )
    assert not patched.get("error"), patched
    assert (home / "proj" / "notes" / "nl.txt").read_bytes() == b"line two\n"
    found = json.loads(file_tools.search_tool(pattern="line two", path="notes", task_id=task))
    assert found.get("total_count") == 1, found
    shown = json.loads(terminal_tool("cat notes/nl.txt", task_id=task))
    assert shown["output"].strip() == "line two", shown
    clear_session_cwd(task)


def test_file_tools_absolute_and_relative_paths_land_on_the_device(file_tools_on_laptop):
    file_tools, home = file_tools_on_laptop
    spaced = f"{device_path(str(home))}/My Projects/notes v1.txt"
    result = json.loads(file_tools.write_file_tool(spaced, "abs\n", task_id="t1"))
    assert not result.get("error"), result
    assert (home / "My Projects" / "notes v1.txt").read_bytes() == b"abs\n"
    result = json.loads(file_tools.write_file_tool("rel dir/rel notes.txt", "rel", task_id="t1"))
    assert not result.get("error"), result
    assert (home / "rel dir" / "rel notes.txt").read_bytes() == b"rel"
    patched = json.loads(
        file_tools.patch_tool(
            mode="replace", path=spaced, old_string="abs", new_string="patched", task_id="t1"
        )
    )
    assert not patched.get("error"), patched
    assert (home / "My Projects" / "notes v1.txt").read_bytes() == b"patched\n"


def test_file_tool_caches_follow_the_target(file_tools_on_laptop, monkeypatch):
    """Core resolves rg once per ShellFileOperations (file_operations_search.py:523-551); after a
    switch core's public clear_file_ops_cache drops that object (file_tools.py:377-399), so the next
    file tool on the device never runs the path the server resolved. The call that sees the switch
    still holds the old object: environment.target_changed, from /hands use, runs before it."""
    from tools import file_operations_search

    file_tools, home = file_tools_on_laptop
    monkeypatch.setattr(file_operations_search, "_bundled_rg", lambda: "/opt/hermes/pm/ripgrep/rg")
    store.set_session_target("s1", "server")
    ops = file_tools._get_file_ops("t1")
    ops.search(pattern="anything", path=".", target="content")
    assert ops._rg_resolution_cache.get("rg") == "/opt/hermes/pm/ripgrep/rg"
    store.set_session_target("s1", "laptop")
    ops.search(pattern="anything", path=".", target="content")  # sees the switch, drops the object
    fresh = file_tools._get_file_ops("t1")
    assert fresh is not ops and not fresh._rg_resolution_cache
    seen = []
    real = fresh.env.execute

    def spy(command, cwd="", **kwargs):
        seen.append(command)
        return real(command, cwd, **kwargs)

    monkeypatch.setattr(fresh.env, "execute", spy)
    fresh.search(pattern="anything", path=".", target="content")
    assert seen and not any("/opt/hermes/pm/ripgrep/rg" in command for command in seen), seen


@pytest.mark.skipif(
    os.name == "nt",
    reason="core expands ~ with the host's os.path (file_tools_paths.py:46-49), so on a Windows "
    "gateway it is a Windows path; the gateway runs on Linux (covered there and by the mapping tests)",
)
def test_file_tools_tilde_path_lands_in_the_device_home(file_tools_on_laptop, monkeypatch):
    import hermes_constants

    file_tools, home = file_tools_on_laptop
    monkeypatch.setattr(
        hermes_constants, "get_subprocess_home", lambda env=None: "/home/gateway-user"
    )
    result = json.loads(file_tools.write_file_tool("~/tilde notes.txt", "tilde\n", task_id="t1"))
    assert not result.get("error"), result
    assert (home / "tilde notes.txt").read_bytes() == b"tilde\n"
    patched = json.loads(
        file_tools.patch_tool(
            mode="replace",
            path="~/tilde notes.txt",
            old_string="tilde",
            new_string="mapped",
            task_id="t1",
        )
    )
    assert not patched.get("error"), patched
    assert (home / "tilde notes.txt").read_bytes() == b"mapped\n"


def test_the_prompt_probe_touches_no_target_and_no_store(
    laptop, hands_backend, monkeypatch, tmp_path
):
    from agent import prompt_builder

    hub, device, home = laptop
    monkeypatch.setenv("TERMINAL_ENV", "hands")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    prompt_builder._clear_backend_probe_cache()
    try:
        with Agent(hub, device, bash_job) as agent:
            assert prompt_builder._probe_remote_backend("hands") is None
        assert agent.jobs == [] and store.get_last_run("s1") is None
    finally:
        prompt_builder._clear_backend_probe_cache()


def test_background_job_follows_its_target_across_a_switch(laptop):
    from tools.process_registry import process_registry

    hub, device, home = laptop
    with Agent(hub, device, bash_job) as agent:
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        session = process_registry.spawn_via_env(
            env, "echo bg on ${HANDS_FAKE_DEVICE:-server}; sleep 30", task_id="bg-test"
        )
        assert session.pid is not None
        store.set_session_target("s1", "server")  # /hands use server
        assert env.execute("echo ${HANDS_FAKE_DEVICE:-server}")["output"].strip() == "server"
        deadline = time.monotonic() + 20
        while "bg on device" not in process_registry.poll(session.id)["output_preview"]:
            assert time.monotonic() < deadline, "the registry's poll never reached the device"
            time.sleep(0.2)
        seen = len(agent.jobs)
        process_registry.kill_process(session.id)
        assert any(f"kill {session.pid} 2>/dev/null" in job["script"] for job in agent.jobs[seen:])
        deadline = time.monotonic() + 10
        while not process_registry.get(session.id).exited:
            assert time.monotonic() < deadline, "the background job was not marked killed"
            time.sleep(0.1)
        # The poller makes one more round after a kill (process_registry.py:1421-1427): let it
        # finish while the device still answers, so it never reaches a later test's client.
        session._reader_thread.join(10)


def test_a_device_offline_blip_keeps_a_background_job_tracked(laptop, monkeypatch):
    from tools.process_registry import process_registry

    hub, device, home = laptop
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        session = process_registry.spawn_via_env(env, "sleep 40; echo finished", task_id="bg-blip")
        assert session.pid is not None
        monkeypatch.setattr(store, "OFFLINE_AFTER", -1)  # the laptop misses heartbeats for a moment
        time.sleep(5)  # two of the poller's cycles (process_registry.py:1424)
        assert not process_registry.get(session.id).exited
        monkeypatch.setattr(store, "OFFLINE_AFTER", 20)
        assert process_registry.kill_process(session.id)["status"] == "killed"
        session._reader_thread.join(10)


class FakeSub:
    """A sub-environment that answers core's background launcher and poller like a live job."""

    def __init__(self, pids):
        self.pids = list(pids)
        self.alive = True
        self.commands = []
        self.cwd = "/"
        self.answer = None  # what the probe and the kill get instead, when set

    def get_temp_dir(self):
        return "/tmp"

    def execute(self, command, cwd="", **kwargs):
        self.commands.append(command)
        if "nohup bash -lc" in command:
            return {"output": f"{self.pids.pop(0)}\n", "returncode": 0}
        if self.answer is not None and command.startswith("kill "):
            return dict(self.answer)
        if command.startswith("kill -0 "):
            return {"output": "0" if self.alive else "1", "returncode": 0}
        if ".exit" in command:
            return {"output": "0", "returncode": 0}
        if ".log" in command:
            return {"output": "0 0\n", "returncode": 0}
        return {"output": "999\n", "returncode": 0}

    def cleanup(self):
        pass


def test_background_kill_routing_is_keyed_by_pid_and_target(laptop):
    from tools.process_registry import process_registry

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    server, device = FakeSub([4242]), FakeSub([4242, 7])
    env._subs = {"server": server, "laptop": device}
    sessions = []
    try:
        shared = process_registry.spawn_via_env(env, "sleep 30", task_id="pid-a")
        sessions.append(shared)
        alone = process_registry.spawn_via_env(env, "sleep 30", task_id="pid-c")
        sessions.append(alone)
        store.set_session_target("s1", "server")
        sessions.append(process_registry.spawn_via_env(env, "sleep 30", task_id="pid-b"))
        assert process_registry.kill_process(alone.id)["status"] == "killed"
        assert (
            "kill 7 2>/dev/null" in device.commands and "kill 7 2>/dev/null" not in server.commands
        )
        refused = process_registry.kill_process(shared.id)
        assert refused["status"] == "error" and "4242" in refused["error"]
        assert not process_registry.get(shared.id).exited
        assert not any(
            command.startswith("kill 4242") for command in server.commands + device.commands
        )
        # A command that only mentions a job file records nothing; a terminal command is not rerouted.
        env.execute("cat /tmp/hermes_bg_zzz.pid")
        assert 999 not in env._background_pids and "zzz" not in env._background
        env.execute(f"cat /tmp/hermes_bg_{shared.id}.log", bounded_capture=True)
        assert server.commands[-1] == f"cat /tmp/hermes_bg_{shared.id}.log"
    finally:
        # End every job, so no registry poller outlives this test: the kill stops the unshared
        # ones, and the pollers see the shared pid's jobs exit (process_registry.py:1460-1470).
        server.alive = device.alive = False
        for session in sessions:
            process_registry.kill_process(session.id)
        for session in sessions:
            session._reader_thread.join(10)
            assert process_registry.get(session.id).exited
            assert not session._reader_thread.is_alive()


def end_jobs(sessions, *subs):
    """Let every poller finish, so none outlives the test (process_registry.py:1460-1470)."""
    from tools.process_registry import process_registry

    for sub in subs:
        sub.alive, sub.answer = False, None
    for session in sessions:
        process_registry.kill_process(session.id)
    for session in sessions:
        session._reader_thread.join(10)
        assert not session._reader_thread.is_alive()


def test_a_pid_counts_on_a_target_only_while_its_job_runs(laptop):
    from tools.process_registry import process_registry

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    server, device = FakeSub([4242]), FakeSub([4242])
    env._subs = {"server": server, "laptop": device}
    sessions = []
    try:
        sessions.append(process_registry.spawn_via_env(env, "sleep 30", task_id="on-device"))
        store.set_session_target("s1", "server")
        sessions.append(process_registry.spawn_via_env(env, "sleep 30", task_id="on-server"))
        server.alive = False  # the server's job ends; the poller reads its exit file
        sessions[1]._reader_thread.join(10)
        assert env._background_pids == {4242: {"laptop"}}
        assert process_registry.kill_process(sessions[0].id)["status"] == "killed"
        assert "kill 4242 2>/dev/null" in device.commands
    finally:
        end_jobs(sessions, server, device)


def test_a_device_that_cannot_answer_keeps_its_job_tracked_and_unkilled(laptop):
    from tools.process_registry import process_registry

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    device = FakeSub([31])
    env._subs = {"laptop": device}
    sessions = []
    try:
        sessions.append(process_registry.spawn_via_env(env, "sleep 30", task_id="quiet"))
        # A sleeping laptop is still online for 20 s, so the probe meets core's own 5 s timeout.
        device.answer = {"output": "[Command timed out after 5s]", "returncode": 124}
        time.sleep(4.5)
        assert not process_registry.get(sessions[0].id).exited
        device.answer = {"output": messages.offline("laptop"), "returncode": relay.UNREACHABLE}
        refused = process_registry.kill_process(sessions[0].id)
        assert refused["status"] == "error" and "offline" in refused["error"]
        assert not process_registry.get(sessions[0].id).exited
        device.answer = {"output": messages.unknown_device("laptop"), "returncode": 255}
        sessions[0]._reader_thread.join(10)
        gone = process_registry.get(sessions[0].id)
        assert gone.exited and gone.completion_reason == "lost"
    finally:
        end_jobs(sessions, device)


def test_a_workdir_equal_to_another_targets_cwd_is_honoured(laptop, tmp_path):
    """Core passes explicit workdir= as given (terminal_tool.py:1039-1040), even after a switch."""
    from tools import terminal_tool

    hub, device, home = laptop
    shared = tmp_path / "shared"
    shared.mkdir()
    (home / "proj").mkdir()
    with Agent(hub, device, bash_job):
        store.set_session_target("s1", "server")
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        terminal_tool._active_environments["s1"] = env
        try:
            server_cwd = run_terminal(
                env, f"cd {shlex.quote(device_path(str(shared)))}"
            )["cwd"]
            store.set_session_target("s1", "laptop")
            environment.target_changed("s1")
            ran = run_terminal(env, "pwd", workdir=server_cwd)
            assert ran["cwd"].endswith("/shared"), ran
            assert run_terminal(env, "pwd")["cwd"] == device_path(str(home))
        finally:
            terminal_tool._active_environments.pop("s1", None)


def test_the_server_starts_in_terminal_cwd_even_when_core_drops_it(laptop, tmp_path, monkeypatch):
    """Core replaces a terminal.cwd under /home, /Users or a drive with "~" for a container backend
    (terminal_tool.py:805-809); the server is this host, as on the local backend."""
    configured = tmp_path / "configured proj"
    configured.mkdir()
    monkeypatch.setenv("TERMINAL_CWD", str(configured))
    store.set_session_target("s1", "server")
    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    assert Path(run_terminal(env, "pwd")["cwd"]) == configured


@pytest.mark.parametrize("target", ["server", "laptop"])
def test_a_first_workdir_without_a_session_key_never_moves_the_start(laptop, monkeypatch, target):
    hub, device, home = laptop
    ctx = Ctx()
    ctx.config["default_target"] = target
    monkeypatch.delenv("HERMES_SESSION_KEY")
    start = Path(os.environ["MESSAGING_CWD"]) if target == "server" else home
    (start / "other").mkdir()
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(ctx, cwd="~", timeout=30)
        env.execute("pwd", cwd=str(start / "other"), bounded_capture=True)  # workdir= first
        after = env.execute("pwd", cwd="~", bounded_capture=True)
    assert not last_line(after).rstrip("/").endswith("other"), after


def test_a_server_workspace_override_owns_the_record_for_a_later_object(laptop):
    """The cwd setter, which core's register_task_env_overrides calls (terminal_tool.py:350-362),
    stores that the record is now the server's, so an object made after an idle reap knows it."""
    from tools import terminal_tool

    hub, device, home = laptop
    workspace = Path(os.environ["MESSAGING_CWD"])
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        run_terminal(env, "true")
        assert store.get_last_run("s1") == "laptop"
        store.set_session_target("s1", "server")
        terminal_tool._active_environments["s1"] = env
        try:
            terminal_tool.register_task_env_overrides("s1", {"cwd": str(workspace)})
        finally:
            terminal_tool._active_environments.pop("s1", None)
            terminal_tool.clear_task_env_overrides("s1")
        assert store.get_last_run("s1") == "server"
        run_terminal(env, "true")
        terminal_tool.record_session_cwd("s1", "/opt/srvapp")  # a Linux gateway's server record
        env.cleanup()
        store.set_session_target("s1", "laptop")
        fresh = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        first = run_terminal(fresh, "pwd")
        assert first["returncode"] == 0 and first["cwd"] == device_path(str(home)), first


def test_a_quoted_rg_path_with_a_space_still_marks_a_search(wired, monkeypatch):
    """Core quotes an rg it found under a home with a space (file_operations_search.py:695-702)."""
    monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
    command = (
        "set -o pipefail; '/c/Users/r b/scoop/shims/rg' --line-number --no-heading "
        "--with-filename '/home/gw/.cache' '/c/Users/r b' 2>/dev/null | head -n 50"
    )
    assert device_env("/c/Users/r b", windows=True)._file_command(command) == command


def test_a_lost_jobs_pid_stops_counting(laptop):
    from tools.process_registry import process_registry

    env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
    device = FakeSub([4242])
    env._subs = {"laptop": device}
    sessions = []
    try:
        sessions.append(process_registry.spawn_via_env(env, "sleep 30", task_id="gone"))
        device.answer = {"output": messages.unknown_device("laptop"), "returncode": 255}
        sessions[0]._reader_thread.join(10)
        assert process_registry.get(sessions[0].id).completion_reason == "lost"
        assert env._background_pids == {}
    finally:
        end_jobs(sessions, device)


def test_a_workdir_equal_to_terminal_cwd_is_honoured_on_a_device(laptop, tmp_path, monkeypatch):
    """Core passes terminal.cwd only when the session has no record (terminal_tool.py:1041-1061)."""
    hub, device, home = laptop
    shared = tmp_path / "shared app"
    shared.mkdir()
    monkeypatch.setenv("TERMINAL_CWD", str(shared))
    with Agent(hub, device, bash_job):
        env = HandsEnvironment(Ctx(), cwd="~", timeout=30)
        run_terminal(env, "mkdir -p sub && cd sub")
        ran = run_terminal(env, "pwd", workdir=str(shared))
    assert ran["cwd"].endswith("/shared app"), ran


def test_relative_paths_after_an_idle_reap_still_follow_the_terminal(file_tools_on_laptop):
    """Core's idle reaper drops the object (terminal_tool_lifecycle.py:135-160); the terminal comes
    back where core recorded it, and so must the anchor of relative file-tool paths."""
    from tools.terminal_tool import terminal_tool
    from tools.terminal_tool_lifecycle import _cleanup_inactive_envs

    file_tools, home = file_tools_on_laptop
    base = device_path(str(home))
    terminal_tool(f"mkdir -p '{base}/proj' && cd '{base}/proj'", task_id="t1")
    _cleanup_inactive_envs(lifetime_seconds=-1)
    written = json.loads(file_tools.write_file_tool("c.txt", "c\n", task_id="t1"))
    assert (home / "proj" / "c.txt").exists(), written
    assert "1|c" in json.loads(file_tools.read_file_tool("c.txt", task_id="t1"))["content"]


def test_target_changed_drops_the_old_targets_not_found_answers(file_tools_on_laptop, monkeypatch):
    """Core answers a read from its 60 s not-found cache before it asks the backend (file_tools.py:
    663-666); /hands use calls target_changed so the new target is asked."""
    file_tools, home = file_tools_on_laptop
    monkeypatch.setenv("HERMES_SESSION_ID", "t1")
    store.set_session_target("s1", "server")
    path = f"{device_path(str(home))}/report.txt"
    miss = json.loads(file_tools.read_file_tool(path, task_id="t1"))
    assert "not found" in (miss.get("error") or "").lower(), miss
    (home / "report.txt").write_text("laptop data\n", encoding="utf-8")
    store.set_session_target("s1", "laptop")
    environment.target_changed("s1")
    hit = json.loads(file_tools.read_file_tool(path, task_id="t1"))
    assert "laptop data" in hit.get("content", ""), hit


def test_after_cd_to_the_root_relative_paths_anchor_on_the_devices_root(file_tools_on_laptop):
    """Core refuses "/" as a sandbox home and would fall back to the gateway's own cwd
    (terminal_tool_config.py:188-192, file_tools_paths.py:276-278)."""
    from tools.file_tools_paths import _resolve_path_for_task
    from tools.terminal_tool import terminal_tool

    file_tools, home = file_tools_on_laptop
    assert json.loads(terminal_tool("cd /", task_id="t1"))["exit_code"] == 0
    assert str(_resolve_path_for_task("notes.txt", "t1")) == "/notes.txt"
