import io
import builtins
import os
import threading
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import psutil
import pytest

from hermeshands_device import executor


def test_terminate_rejects_reused_posix_leader(monkeypatch):
    monkeypatch.setattr(executor, "_LINUX", False)
    killed = []
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor, "os", SimpleNamespace(name="posix", killpg=lambda *args: killed.append(args)))
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 9.0))
    executor._terminate(SimpleNamespace(pid=100), 1.0)
    assert killed == []


def test_leaderless_unknown_group_is_not_owned(monkeypatch):
    monkeypatch.setattr(executor, "_LINUX", False)
    monkeypatch.setattr(executor.psutil, "Process", Mock(side_effect=psutil.NoSuchProcess(100)))
    monkeypatch.setattr(executor.os, "killpg", lambda *args: None, raising=False)
    assert not executor._posix_group_is_ours(100, 1.0)


def test_guardian_requires_registration_ack(monkeypatch):
    guardian = SimpleNamespace(poll=lambda: None, stdin=io.StringIO(), stdout=io.StringIO(""), kill=Mock(), wait=Mock())
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", guardian)
    monkeypatch.setattr(executor.select, "select", lambda *args: ([guardian.stdout], [], []))
    with pytest.raises(RuntimeError, match="guardian"):
        executor._send_to_posix_guardian("add 100 1.0\n")


def test_cancellation_at_popen_boundary_does_not_launch(monkeypatch, tmp_path):
    cancelled = threading.Event()
    monkeypatch.setattr(executor, "resolve_bash", lambda: "bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    original_copy = os.environ.copy

    def environment():
        cancelled.set()
        return original_copy()

    monkeypatch.setattr(executor.os.environ, "copy", environment)
    launch = Mock(side_effect=AssertionError("launched after cancellation"))
    monkeypatch.setattr(executor.subprocess, "Popen", launch)
    with pytest.raises(InterruptedError):
        list(executor.run("echo hi", cancel_event=cancelled))
    launch.assert_not_called()
    assert not list((tmp_path / ".hermes-hands/out").glob("*.sh"))


@pytest.mark.parametrize("reused", [False, True])
def test_guardian_program_checks_members_and_reaps_after_parent_eof(reused):
    killed = []
    identities = {100: 9.0 if reused else 1.0, 101: 2.0}

    def process(pid):
        if pid not in identities:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(pid=pid, create_time=lambda: identities[pid])

    class Input(io.StringIO):
        def readline(self):
            line = super().readline()
            if not line:
                identities.pop(100, None)
            return line

    incoming = Input("add 100 1.0\n")
    outgoing = io.StringIO()
    modules = {
        "os": SimpleNamespace(getpgid=lambda pid: 100, killpg=lambda *args: killed.append(args)),
        "signal": SimpleNamespace(SIGINT=2, SIGHUP=1, SIGKILL=9, SIG_IGN=1, signal=lambda *args: None),
        "sys": SimpleNamespace(stdin=incoming, stdout=outgoing, platform="darwin"),
        "select": SimpleNamespace(select=lambda *args: ([incoming], [], [])),
        "psutil": SimpleNamespace(Process=process, process_iter=lambda: [process(pid) for pid in identities], Error=psutil.Error),
    }
    actual_import = builtins.__import__

    def imports(name, *args, **kwargs):
        return modules[name] if name in modules else actual_import(name, *args, **kwargs)

    namespace = {"__builtins__": {**vars(builtins), "__import__": imports, "print": lambda value, **kwargs: outgoing.write(value + "\n")}}
    exec(executor._POSIX_GUARDIAN_CODE, namespace)
    assert outgoing.getvalue().startswith("ready\nack ")
    assert killed == ([] if reused else [(100, 9)])


def test_guardian_startup_wait_is_bounded_and_failure_closes_child(monkeypatch):
    guardian = SimpleNamespace(poll=lambda: None, stdin=io.StringIO(), stdout=io.StringIO(), kill=Mock(), wait=Mock())
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", None)
    monkeypatch.setattr(executor.subprocess, "Popen", lambda *args, **kwargs: guardian)
    timeouts = []
    monkeypatch.setattr(executor.select, "select", lambda readers, writers, errors, timeout: timeouts.append(timeout) or ([], [], []))
    with pytest.raises(RuntimeError, match="guardian"):
        executor._send_to_posix_guardian("add 100 1.0\n")
    assert len(timeouts) == 1
    assert 0 < timeouts[0] <= executor._POSIX_GUARDIAN_TIMEOUT
    assert guardian.stdin.closed
    guardian.wait.assert_called_once()
    assert executor._POSIX_GUARDIAN is None


def test_posix_group_retains_identifiable_member_after_leader_exit(monkeypatch):
    monkeypatch.setattr(executor, "_LINUX", False)
    identities = {100: 1.0, 101: 2.0}

    def process(pid):
        if pid not in identities:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(pid=pid, create_time=lambda: identities[pid])

    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {})
    monkeypatch.setattr(executor.os, "getpgid", lambda pid: 100, raising=False)
    monkeypatch.setattr(executor.psutil, "Process", process)
    monkeypatch.setattr(executor.psutil, "process_iter", lambda: [process(pid) for pid in identities])
    assert executor._posix_group_is_ours(100, 1.0)
    identities.pop(100)
    assert executor._posix_group_is_ours(100, 1.0)
    identities[101] = 3.0
    assert not executor._posix_group_is_ours(100, 1.0)


def test_cancellation_before_windows_resume_keeps_process_suspended(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "_LINUX", False)
    cancelled = threading.Event()
    process = SimpleNamespace(pid=100, poll=lambda: None, wait=Mock())
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(executor, "resolve_bash", lambda: "bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 1.0))
    monkeypatch.setattr(executor, "_create_windows_job", lambda *args: 111)
    resume = Mock()
    terminate = Mock()
    monkeypatch.setattr(executor, "_resume_windows_process", resume)
    monkeypatch.setattr(executor, "_terminate", terminate)
    monkeypatch.setattr(executor, "_close_windows_job", Mock())
    with pytest.raises(InterruptedError):
        list(executor.run("echo hi", cancel_event=cancelled, on_start=lambda *args: cancelled.set()))
    resume.assert_not_called()
    terminate.assert_called_once_with(process, 1.0)


def test_guardian_registration_failure_terminates_the_new_job(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "_LINUX", False)
    process = SimpleNamespace(pid=100, poll=lambda: None, wait=Mock())
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "posix"}))
    monkeypatch.setattr(executor, "resolve_bash", lambda: "bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 1.0))
    monkeypatch.setattr(executor, "_create_windows_job", lambda *args: None)
    monkeypatch.setattr(executor, "_send_to_posix_guardian", lambda line: None)
    monkeypatch.setattr(executor, "_track_posix_group", Mock(side_effect=RuntimeError("guardian registration failed")))
    terminate = Mock()
    monkeypatch.setattr(executor, "_terminate", terminate)
    with pytest.raises(RuntimeError, match="guardian"):
        list(executor.run("echo hi"))
    terminate.assert_called_once_with(process, 1.0)
    assert not list((tmp_path / ".hermes-hands/out").glob("*.sh"))


def test_posix_launch_waits_for_registration_before_executing_bash(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "posix"}))
    monkeypatch.setattr(executor, "resolve_bash", lambda: "bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor, "_send_to_posix_guardian", lambda line: None)
    captured = []

    def launch(args, **kwargs):
        captured.append((args, kwargs))
        raise OSError("launch captured")

    monkeypatch.setattr(executor.subprocess, "Popen", launch)
    with pytest.raises(OSError, match="launch captured"):
        list(executor.run("echo hi"))
    args, kwargs = captured[0]
    assert args[0] == executor.sys.executable
    assert "os.read" in args[3]
    assert kwargs["pass_fds"]


@pytest.mark.parametrize("wait_fails", [False, True])
def test_guardian_failure_terminates_already_protected_groups(monkeypatch, wait_fails):
    killed = []
    guardian = SimpleNamespace(poll=lambda: None, stdin=io.StringIO(), stdout=io.StringIO(), kill=Mock(), wait=Mock())
    if wait_fails:
        guardian.wait.side_effect = subprocess.TimeoutExpired("guardian", 0)
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", guardian)
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {100: 1.0})
    monkeypatch.setattr(executor, "_posix_group_is_ours", lambda *args: True)
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor.os, "killpg", lambda *args: killed.append(args), raising=False)
    monkeypatch.setattr(executor.select, "select", lambda *args: ([], [], []))
    with pytest.raises(RuntimeError, match="guardian"):
        executor._send_to_posix_guardian("add 200 2.0\n")
    assert killed == [(100, 9)]


@pytest.mark.parametrize("release", [b"", b"1"])
def test_exact_launch_wrapper_only_executes_after_release(release):
    child = subprocess.run(
        [sys.executable, "-I", "-c", executor._POSIX_LAUNCH_CODE, "0", sys.executable, "-I", "-c", "print('body-ran')"],
        input=release, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
    )
    assert child.returncode == (0 if release else 130), child.stderr
    assert child.stdout.strip() == (b"body-ran" if release else b""), child.stderr


@pytest.mark.parametrize("identity_missing", [False, True])
def test_failed_launch_closes_barrier_before_wait_and_cleans_files(monkeypatch, tmp_path, identity_missing):
    monkeypatch.setattr(executor, "_LINUX", False)
    closed = []

    def wait(timeout=None):
        assert closed == [90, 91], "barrier still open while waiting for the blocked wrapper"
        return 130

    process = SimpleNamespace(pid=100, poll=lambda: None, wait=wait)
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "posix", "pipe": lambda: (90, 91), "close": closed.append}))
    monkeypatch.setattr(executor, "resolve_bash", lambda: "bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor.subprocess, "Popen", lambda *args, **kwargs: process)
    if identity_missing:
        monkeypatch.setattr(executor.psutil, "Process", Mock(side_effect=psutil.NoSuchProcess(100)))
    else:
        monkeypatch.setattr(executor.psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 1.0))
    monkeypatch.setattr(executor, "_send_to_posix_guardian", lambda line: None)
    monkeypatch.setattr(executor, "_track_posix_group", Mock(side_effect=RuntimeError("guardian registration failed")))
    monkeypatch.setattr(executor, "_terminate", lambda *args: None)
    error = psutil.NoSuchProcess if identity_missing else RuntimeError
    with pytest.raises(error):
        list(executor.run("echo hi", stdin="private"))
    assert closed == [90, 91]
    assert not list((tmp_path / ".hermes-hands/out").iterdir())


def test_tracking_bounds_the_old_group_check_and_the_new_registration_separately(monkeypatch):
    deadlines = []
    clock = [10.0]

    def send(line, deadline=None):
        deadlines.append((line.split()[0], deadline))
        clock[0] += 0.5

    monkeypatch.setattr(executor, "_POSIX_GROUPS", {100: 1.0, 200: 2.0})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {})
    monkeypatch.setattr(executor, "_posix_group_is_ours", lambda *args, **kwargs: False)
    monkeypatch.setattr(executor.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(executor, "_send_to_posix_guardian", send)
    executor._track_posix_group(300, 3.0)
    assert deadlines == [("checkall", 12.0), ("del", 12.0), ("del", 12.0), ("add", 13.5)]


def test_stop_with_busy_group_lock_closes_guardian_without_waiting(monkeypatch):
    busy = threading.Lock()
    busy.acquire()
    done = threading.Event()
    errors = []
    guardian = SimpleNamespace(stdin=io.StringIO())
    groups = {100: 1.0}
    members = {100: {100: 1.0}}
    send = Mock()
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "posix", "killpg": lambda *args: None}))
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor, "_POSIX_GROUPS_LOCK", busy)
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", guardian)
    monkeypatch.setattr(executor, "_POSIX_GROUPS", groups)
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", members)
    monkeypatch.setattr(executor, "_posix_group_is_ours", lambda *args: True)
    monkeypatch.setattr(executor, "_send_to_posix_guardian", send)

    def stop():
        try:
            executor._terminate_posix_groups(time.monotonic() + 0.02)
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()

    worker = threading.Thread(target=stop, daemon=True)
    worker.start()
    try:
        assert done.wait(0.3), "shutdown blocked on the group lock beyond its deadline"
        assert errors == []
        assert guardian.stdin.closed
        assert groups == {100: 1.0}
        assert members == {100: {100: 1.0}}
        send.assert_not_called()
    finally:
        busy.release()
        worker.join(1)
