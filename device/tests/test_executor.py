import os
import base64
import ctypes
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import psutil

from hermeshands_device import executor


@pytest.mark.parametrize("platform", ["nt", "posix"])
def test_close_windows_job_accepts_missing_process(monkeypatch, platform):
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": platform}))
    executor._close_windows_job(None, None)


def test_process_creation_failure_keeps_original_error(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "resolve_bash", lambda: "bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor, "_send_to_posix_guardian", lambda line, deadline=None: None)
    popen = Mock(side_effect=OSError("original launch error"))
    monkeypatch.setattr(executor.subprocess, "Popen", popen)
    with pytest.raises(OSError, match="original launch error"):
        list(executor.run("echo hi"))
    popen.assert_called_once()


def test_windows_cleanup_deadline_closes_stubborn_job(monkeypatch):
    kernel32 = SimpleNamespace(TerminateJobObject=Mock(return_value=1), CloseHandle=Mock())
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel32, raising=False)
    monkeypatch.setattr(executor, "_WINDOWS_JOBS", {123: 456})
    monkeypatch.setattr(executor, "_windows_job_has_active_processes", lambda job: True)
    started = time.monotonic()
    executor._terminate_windows_jobs(started + 0.05)
    assert time.monotonic() - started < 0.3
    assert executor._WINDOWS_JOBS == {}
    kernel32.CloseHandle.assert_called_once()


def test_windows_cleanup_logs_oserror_and_closes_handle(monkeypatch, caplog):
    kernel32 = SimpleNamespace(TerminateJobObject=Mock(side_effect=OSError("denied")), CloseHandle=Mock())
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel32, raising=False)
    monkeypatch.setattr(executor, "_WINDOWS_JOBS", {123: 456})
    monkeypatch.setattr(executor, "_windows_job_has_active_processes", lambda job: True)
    executor._terminate_windows_jobs(time.monotonic() + 0.05)
    assert "denied" in caplog.text
    assert executor._WINDOWS_JOBS == {}
    kernel32.CloseHandle.assert_called_once()


def test_retained_windows_jobs_share_one_reaper(monkeypatch):
    watchers = []
    monkeypatch.setattr(executor, "_WINDOWS_REAPING", {})
    monkeypatch.setattr(executor, "_WINDOWS_REAPER", None)
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(executor, "_WINDOWS_JOBS", {pid: pid + 100 for pid in range(10)})
    monkeypatch.setattr(executor, "_windows_job_has_active_processes", lambda job: True)
    monkeypatch.setattr(executor.threading, "Thread", lambda **kwargs: watchers.append(kwargs) or SimpleNamespace(start=lambda: None))
    for pid in range(10):
        executor._close_windows_job(SimpleNamespace(pid=pid), pid + 100, keep_active=True)
    assert len(watchers) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows kill-on-close containment")
def test_killing_executor_host_closes_job_and_kills_running_child(tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("Git Bash is unavailable")
    pid_file = tmp_path / "contained-child.pid"
    child_code = f"import os,time; from pathlib import Path; Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)"
    host_code = (
        "import shlex,sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from hermeshands_device import executor\n"
        "executor.Path.home = lambda: Path(sys.argv[2])\n"
        "executor.resolve_bash = lambda: sys.argv[3]\n"
        "list(executor.run(shlex.quote(sys.executable.replace('\\\\', '/')) + ' -c ' + shlex.quote(sys.argv[4]), timeout=60))\n"
    )
    host = subprocess.Popen(
        [sys.executable, "-u", "-c", host_code, str(Path(executor.__file__).parents[1]), str(tmp_path), bash, child_code],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    child = None
    try:
        deadline = time.monotonic() + 10
        while not pid_file.exists() and host.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert host.poll() is None, host.communicate(timeout=1)
        assert pid_file.exists()
        child = psutil.Process(int(pid_file.read_text(encoding="utf-8-sig")))
        host.kill()
        host.wait(timeout=3)
        _, alive = psutil.wait_procs([child], timeout=3)
        assert alive == []
    finally:
        if host.poll() is None:
            host.kill()
        host.communicate(timeout=3)
        if child is not None and child.is_running():
            child.kill()
            child.wait(timeout=3)


def test_windowsapps_which_candidate_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "none"))
    monkeypatch.delenv("HERMES_HANDS_BASH", raising=False)
    monkeypatch.setattr(
        shutil, "which", lambda name: r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\bash.exe"
    )
    monkeypatch.setattr(os.path, "isfile", lambda path: True)
    assert executor.resolve_bash() is None


def test_resolve_bash_probes_each_candidate_once(monkeypatch, tmp_path):
    bash = tmp_path / "bash.exe"
    bash.write_bytes(b"")
    monkeypatch.setattr(executor, "_PROBED", {})
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setenv("HERMES_HANDS_BASH", str(bash))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "none"))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    probes = []
    monkeypatch.setattr(
        executor.subprocess, "run", lambda args, **kwargs: probes.append(args) or subprocess.CompletedProcess(args, 0)
    )
    assert executor.resolve_bash() == executor.resolve_bash() == str(bash)
    assert probes == [[str(bash), "-c", "exit 0"]]
    bash.unlink()
    assert executor.resolve_bash() is None  # a bash that went away is still noticed


def test_cached_bash_is_reprobed_when_file_changes(monkeypatch, tmp_path):
    bash = tmp_path / "bash.exe"
    bash.write_bytes(b"old")
    monkeypatch.setattr(executor, "_PROBED", {})
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setenv("HERMES_HANDS_BASH", str(bash))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "none"))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    probes = []

    def probe(args, **kwargs):
        probes.append(args)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(executor.subprocess, "run", probe)
    assert executor.resolve_bash() == str(bash)
    bash.write_bytes(b"replacement with a different size")
    assert executor.resolve_bash() == str(bash)
    assert probes == [[str(bash), "-c", "exit 0"]] * 2


def test_failed_cached_bash_reprobe_uses_next_candidate(monkeypatch, tmp_path):
    preferred = tmp_path / "preferred.exe"
    fallback = tmp_path / "fallback.exe"
    preferred.write_bytes(b"old")
    fallback.write_bytes(b"bash")
    monkeypatch.setattr(executor, "_PROBED", {})
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setenv("HERMES_HANDS_BASH", str(preferred))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "none"))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: str(fallback))
    probes = []

    def probe(args, **kwargs):
        probes.append(args[0])
        return subprocess.CompletedProcess(args, int(args[0] == str(preferred) and probes.count(str(preferred)) > 1))

    monkeypatch.setattr(executor.subprocess, "run", probe)
    assert executor.resolve_bash() == str(preferred)
    preferred.write_bytes(b"replacement with a different size")
    assert executor.resolve_bash() == str(fallback)
    assert probes == [str(preferred), str(preferred), str(fallback)]


def test_real_bash_execution(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    chunks = b"".join(executor.run("echo hi", timeout=5))
    assert chunks.strip() == b"hi"


def test_executor_marks_job_environment(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    output = b"".join(executor.run('printf "%s" "$HERMES_HANDS_JOB"', timeout=5))

    assert output == b"1"


@pytest.mark.skipif(os.name != "nt", reason="MSYS switch conversion is Windows-only")
def test_cmd_slash_switch_can_be_passed_without_msys_path_conversion(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("Git Bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    output = b"".join(executor.run("MSYS_NO_PATHCONV=1 cmd /c echo x", timeout=15))

    assert output.strip() == b"x"


@pytest.mark.skipif(os.name != "nt", reason="Windows background-job containment")
def test_background_process_survives_shell_exit_until_job_finishes(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("Git Bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor, "_WINDOWS_JOBS", {})
    pid_file = tmp_path / "background.pid"
    script_file = tmp_path / "background.py"
    script_file.write_text(
        f"import os, time\nopen({str(pid_file)!r}, 'w').write(str(os.getpid()))\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    started = time.monotonic()
    output = b"".join(executor.run(
        f'nohup python "{script_file.as_posix()}" >/dev/null 2>&1 & child=$!; '
        f'for i in {{1..100}}; do test -e "{pid_file.as_posix()}" && break; sleep 0.01; done; '
        "echo $child",
        timeout=15,
    ))
    elapsed = time.monotonic() - started
    assert output.splitlines()[0].isdigit()
    deadline = time.monotonic() + 15
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert pid_file.exists()
    assert elapsed < 17
    child_pid = int(pid_file.read_text(encoding="utf-8-sig"))
    job_pids = tuple(executor._WINDOWS_JOBS)
    try:
        assert psutil.pid_exists(child_pid)
        assert len(job_pids) == 1
    finally:
        if psutil.pid_exists(child_pid):
            psutil.Process(child_pid).kill()
        if job_pids:
            deadline = time.monotonic() + 2
            while job_pids[0] in executor._WINDOWS_JOBS and time.monotonic() < deadline:
                time.sleep(0.05)
            assert job_pids[0] not in executor._WINDOWS_JOBS


def test_chatty_background_writer_is_bounded_after_shell_exit(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor, "POST_EXIT_DRAIN_LIMIT", 0.2)
    pid_file = tmp_path / "writer.pid"
    script_file = tmp_path / "writer.py"
    script_file.write_text(
        f"import os, sys, time\nopen({str(pid_file)!r}, 'w').write(str(os.getpid()))\nwhile True:\n print('tick', flush=True)\n time.sleep(0.01)\n",
        encoding="utf-8",
    )
    started = time.monotonic()
    truncated = []
    command = (
        f'python "{script_file.as_posix()}" & '
        f'for i in {{1..100}}; do test -s "{pid_file.as_posix()}" && break; sleep 0.01; done; '
        "sleep 0.1; echo parent-exit"
    )
    chunks = b"".join(executor.run(command, timeout=15, on_truncated=lambda: truncated.append(True)))
    elapsed = time.monotonic() - started
    deadline = time.monotonic() + 15
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if pid_file.exists():
        child_pid = int(pid_file.read_text(encoding="utf-8-sig"))
        if psutil.pid_exists(child_pid):
            psutil.Process(child_pid).kill()
    assert b"parent-exit" in chunks
    assert b"tick" in chunks or b"[output truncated after the post-exit idle limit]" in chunks or b"[device timeout]" in chunks
    assert truncated == [True]
    assert elapsed < 17


def test_post_exit_drain_budget_ignores_pre_exit_backpressure(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor, "OUTPUT_QUEUE_SIZE", 1)
    monkeypatch.setattr(executor, "POST_EXIT_DRAIN_LIMIT", 0.2)
    pid_file = tmp_path / "writer.pid"
    script = (
        "head -c 65536 /dev/zero | tr '\\000' x; sleep 0.6; "
        f'(for i in {{1..100}}; do printf y; sleep 0.05; done) & echo $! > "{pid_file.as_posix()}"; '
        "printf 'PARENT_EXIT\\n'"
    )
    output = bytearray()
    exit_marker_at = None
    truncated_after_exit = None
    slowed = False
    started = time.monotonic()
    try:
        for chunk in executor.run(script, timeout=10):
            output.extend(chunk)
            if exit_marker_at is None and b"PARENT_EXIT" in output:
                exit_marker_at = time.monotonic()
            if exit_marker_at is not None and b"[output truncated after the post-exit idle limit]" in chunk:
                truncated_after_exit = time.monotonic() - exit_marker_at
            if not slowed and chunk and all(byte == ord("x") for byte in chunk):
                slowed = True
                time.sleep(0.5)
    finally:
        if pid_file.exists():
            pid = int(pid_file.read_text(encoding="utf-8-sig"))
            if psutil.pid_exists(pid):
                psutil.Process(pid).kill()

    assert exit_marker_at is not None
    assert truncated_after_exit is not None
    assert truncated_after_exit < 0.5
    assert time.monotonic() - started < 5


def test_large_script_runs_from_temp_file_and_is_removed(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    script = "printf x\n" * 100_000
    assert b"".join(executor.run(script, timeout=30)) == b"x" * 100_000
    assert not list((tmp_path / ".hermes-hands/out").glob("*.sh"))


def test_timeout_kills_process(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "resolve_bash", lambda: shutil.which("bash"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    started = time.monotonic()
    chunks = b"".join(executor.run("sleep 10", timeout=0.1))
    assert b"timeout" in chunks
    assert time.monotonic() - started < 3


@pytest.mark.skipif(os.name == "nt", reason="POSIX deadline timer race")
def test_posix_timeout_always_reports_timeout_marker(monkeypatch, tmp_path):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    for _ in range(20):
        exits = []
        chunks = b"".join(executor.run("sleep 1", timeout=0.01, on_exit=exits.append))
        assert b"[device timeout]" in chunks
        assert exits == [124]


@pytest.mark.skipif(os.name == "nt", reason="POSIX process group is covered by timeout test")
def test_grandchild_killed_on_posix(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "resolve_bash", lambda: shutil.which("bash"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    chunks = b"".join(executor.run("sleep 30 & echo $!; wait", timeout=0.2))
    child_pid = int(chunks.splitlines()[0])
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)  # windows-footgun: ok -- POSIX-only test for killpg behavior


@pytest.mark.skipif(os.name == "nt", reason="POSIX process group is covered by timeout test")
def test_recorded_process_reap_kills_process_group(monkeypatch):
    monkeypatch.setattr(executor, "_LINUX", False)
    calls = []
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: type("Process", (), {"create_time": lambda self: 1.0})())
    monkeypatch.setattr(executor.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    executor.terminate_recorded(4321, 1.0)
    assert calls == [(4321, getattr(executor.signal, "SIGKILL", executor.signal.SIGTERM))]


@pytest.mark.skipif(os.name != "nt", reason="Windows taskkill tree behavior")
def test_grandchild_killed_on_windows(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("Git Bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    bash_python = subprocess.run(
        [bash, "-c", "command -v python"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5,
    )
    if bash_python.returncode:
        pytest.skip("Python is unavailable inside Git Bash")
    script_file = tmp_path / "spawn-grandchild.py"
    script_file.write_text(
        "import subprocess, sys, time\nchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\nprint(child.pid, flush=True)\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    chunks = b"".join(executor.run(f'python "{script_file.as_posix()}"', timeout=30))
    child_pid = int(chunks.splitlines()[0])
    deadline = time.monotonic() + 2
    while psutil.pid_exists(child_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not psutil.pid_exists(child_pid)


def test_output_cap(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor, "MAX_OUTPUT", 5)
    output = b"".join(executor.run("printf 123456789", timeout=5))
    assert output.startswith(b"12345")
    assert b"truncated" in output
    assert (tmp_path / ".hermes-hands/out/job.log").read_bytes() == b"12345"


def test_stdin_is_staged_byte_exact_and_removed(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert b"".join(executor.run("cat", stdin="hello \u4e2d\u6587\n", timeout=5)) == "hello \u4e2d\u6587\n".encode()
    assert not list((tmp_path / ".hermes-hands/out").glob("tmp*"))


def test_stdin_uses_surrogateescape_and_is_removed(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    raw = b"before\xffafter"
    stdin = raw.decode("utf-8", errors="surrogateescape")
    assert b"".join(executor.run("cat", stdin=stdin, timeout=5)) == raw
    assert not list((tmp_path / ".hermes-hands/out").glob("*.stdin"))


def test_stdin_base64_is_staged_byte_exact_and_removed(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    raw = b"before\xffafter"
    encoded = base64.b64encode(raw).decode("ascii")
    assert b"".join(executor.run("cat", stdin_b64=encoded, timeout=5)) == raw
    assert not list((tmp_path / ".hermes-hands/out").glob("*.stdin"))


def test_terminate_kills_checked_descendants_after_job_termination(monkeypatch):
    monkeypatch.setattr(executor, "_LINUX", False)
    events = []

    class Process:
        def __init__(self, pid, created, children=()):
            self.pid = pid
            self.created = created
            self.descendants = children

        def create_time(self):
            return self.created

        def children(self, recursive=False):
            events.append(("snapshot", self.pid, recursive))
            return self.descendants

        def kill(self):
            events.append(("kill", self.pid))

    escaped = Process(8765, 2.0)

    class ReusedProcess(Process):
        checks = 0

        def create_time(self):
            self.checks += 1
            return 2.0 if self.checks == 1 else 3.0

    reused = ReusedProcess(9876, 2.0)
    root = Process(4321, 1.0, (escaped, reused))
    processes = {process.pid: process for process in (root, escaped, reused)}
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: processes[pid])
    monkeypatch.setattr(
        executor,
        "_terminate_windows_job",
        lambda pid, start_time: events.append(("job", pid, start_time)) or True,
    )

    executor._terminate(SimpleNamespace(pid=4321), 1.0)

    assert events == [
        ("snapshot", 4321, True),
        ("job", 4321, 1.0),
        ("kill", 8765),
        ("kill", 4321),
    ]


def test_terminate_does_not_kill_reused_root_pid(monkeypatch):
    monkeypatch.setattr(executor, "_LINUX", False)
    calls = []

    class ReusedProcess:
        checks = 0

        def create_time(self):
            self.checks += 1
            return 1.0 if self.checks == 1 else 2.0

        def children(self, recursive=False):
            return []

        def kill(self):
            calls.append("kill")

    process = ReusedProcess()
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: process)
    monkeypatch.setattr(
        executor,
        "_terminate_windows_job",
        lambda pid, start_time: calls.append(("job", pid, start_time)) or True,
    )

    executor.terminate_recorded(4321, 1.0)

    assert process.checks == 2
    assert calls == [("job", 4321, 1.0)]


@pytest.mark.parametrize("failure", ["record", "start"])
def test_executor_start_failure_kills_process_and_cleans_staged_files(monkeypatch, tmp_path, failure):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    killed = []
    terminate_process = executor._terminate

    def terminate(proc, started):
        killed.append(proc.pid)
        terminate_process(proc, started)

    monkeypatch.setattr(executor, "_terminate", terminate)
    if failure == "record":
        monkeypatch.setattr(executor, "record_process", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
        on_start = lambda *args: None
        error = OSError
    else:
        on_start = lambda *args: (_ for _ in ()).throw(RuntimeError("start failed"))
        error = RuntimeError

    with pytest.raises(error):
        list(executor.run("sleep 30", job_id=f"failure-{failure}", stdin="private input", on_start=on_start))
    assert len(killed) == 1
    out = tmp_path / ".hermes-hands" / "out"
    assert not list(out.glob("*.sh"))
    assert not list(out.glob("*.stdin"))
    assert not list(out.glob("*.process.json"))


@pytest.mark.skipif(os.name != "nt", reason="MSYS child process behavior")
def test_msys_child_is_killed_on_timeout(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("Git Bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    token = f"hands-{time.time_ns()}"
    chunks = b"".join(executor.run(f"sleep 0.5; yes {token} > /dev/null; wait", timeout=2))
    assert b"[device timeout]" in chunks
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        survivor = [p for p in psutil.process_iter(["name", "cmdline"]) if p.info["name"] and p.info["name"].lower() == "yes.exe" and token in " ".join(p.info["cmdline"] or [])]
        if not survivor:
            break
        time.sleep(0.05)
    assert not survivor


def test_orphaned_stdin_files_are_reaped_at_start(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    out = tmp_path / ".hermes-hands" / "out"
    out.mkdir(parents=True)
    staged = out / "abandoned.stdin"
    staged.write_bytes(b"left over from an interrupted run")
    executor.reap_recorded_processes()
    assert not staged.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Python UTF-8 environment")
def test_windows_python_utf8_environment_is_passed_to_child(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("Git Bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    output = b"".join(executor.run("python -c 'import os; print(os.environ[\"PYTHONUTF8\"] + \" \" + os.environ[\"PYTHONIOENCODING\"])'", timeout=15))
    assert output.strip() == b"1 utf-8"


def test_output_cap_reports_nonzero_exit(monkeypatch, tmp_path):
    bash = executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor, "MAX_OUTPUT", 5)
    exits = []
    capped = []
    list(executor.run("printf 123456789", timeout=5, on_exit=exits.append, on_capped=lambda: capped.append(True)))
    assert exits == [1]
    assert capped == [True]


def test_reader_queue_is_bounded():
    assert 0 < executor.OUTPUT_QUEUE_SIZE < 1024


def test_recorded_process_is_reaped_and_record_removed(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    killed = []
    monkeypatch.setattr(executor, "terminate_recorded", lambda pid, created: killed.append((pid, created)))
    executor.record_process("old-job", 1234, 5678.5)
    record = executor.record_path("old-job")
    assert record.exists()
    executor.reap_recorded_processes()
    assert killed == [(1234, 5678.5)]
    assert not record.exists()


@pytest.mark.parametrize("contents", ["", '{"pid": 12'])
def test_corrupt_process_record_does_not_stop_reaping(monkeypatch, tmp_path, contents):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    out = tmp_path / ".hermes-hands" / "out"
    out.mkdir(parents=True)
    record = out / "torn.process.json"
    record.write_text(contents, encoding="utf-8")
    executor.reap_recorded_processes()
    assert not record.exists()


def test_reaped_process_start_time_mismatch_does_not_kill(monkeypatch):
    calls = []
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: type("Process", (), {"create_time": lambda self: 1.0, "kill": lambda self: calls.append(pid)})())
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    executor.terminate_recorded(1234, 2.0)
    assert calls == []


def test_recorded_posix_reap_kills_the_process_group(monkeypatch):
    monkeypatch.setattr(executor, "_LINUX", False)
    killed = []
    process = type("Process", (), {"create_time": lambda self: 2.0})()
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "posix"}))
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: process)
    monkeypatch.setattr(executor.os, "killpg", lambda pid, sig: killed.append((pid, sig)), raising=False)
    executor.terminate_recorded(1234, 2.0)
    assert killed == [(1234, getattr(executor.signal, "SIGKILL", executor.signal.SIGTERM))]


def test_open_windows_job_requests_terminate_access(monkeypatch):
    kernel32 = SimpleNamespace(OpenJobObjectW=Mock(return_value=4321))
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel32, raising=False)

    assert executor._open_windows_job(1234, 1.0) == 4321
    assert kernel32.OpenJobObjectW.call_args.args[0] == 0x0008


def test_create_windows_job_sets_kill_on_close_and_resumes_after_assignment(monkeypatch):
    events = []
    kernel32 = SimpleNamespace(
        CreateJobObjectW=Mock(return_value=111),
        SetInformationJobObject=Mock(side_effect=lambda job, kind, info, size: events.append(("set", info._obj.BasicLimitInformation.LimitFlags)) or 1),
        AssignProcessToJobObject=Mock(side_effect=lambda job, process: events.append(("assign", job.value, process.value)) or 1),
        OpenThread=Mock(side_effect=lambda access, inherit, thread_id: events.append(("open-thread", access, thread_id)) or 222),
        ResumeThread=Mock(side_effect=lambda thread: events.append(("resume-thread", thread.value)) or 1),
        CloseHandle=Mock(side_effect=lambda handle: events.append(("close-handle", handle.value))),
        TerminateJobObject=Mock(),
    )
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel32, raising=False)
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(kernel32=kernel32), raising=False)
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: SimpleNamespace(threads=lambda: [SimpleNamespace(id=333)]))
    monkeypatch.setattr(executor, "_WINDOWS_JOBS", {})
    process = SimpleNamespace(pid=1234, _handle=444)

    job = executor._create_windows_job(process, 5.0)
    assert events == [("set", 0x00002000), ("assign", 111, 444)]
    executor._resume_windows_process(process)

    assert job == 111
    assert events == [
        ("set", 0x00002000),
        ("assign", 111, 444),
        ("open-thread", 0x0002, 333),
        ("resume-thread", 222),
        ("close-handle", 222),
    ]
    assert executor._WINDOWS_JOBS == {1234: 111}


@pytest.mark.parametrize("cancelled", [False, True])
def test_windows_job_runs_on_start_before_the_process_is_resumed(monkeypatch, tmp_path, cancelled):
    monkeypatch.setattr(executor, "_LINUX", False)
    events = []

    class Process:
        pid = 1234
        stdout = None
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

    process = Process()
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(executor, "resolve_bash", lambda: "bash.exe")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 1.0))
    monkeypatch.setattr(executor.subprocess, "Popen", lambda args, **kwargs: process)
    monkeypatch.setattr(executor, "_create_windows_job", lambda proc, created: events.append("job") or 111)
    monkeypatch.setattr(executor, "_resume_windows_process", lambda proc: events.append("resume"))
    monkeypatch.setattr(executor.threading, "Timer", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("past start")))
    monkeypatch.setattr(executor, "_terminate", lambda *args: None)
    monkeypatch.setattr(executor, "_close_windows_job", lambda *args, **kwargs: None)

    def on_start(proc, created):
        events.append("on_start")
        if cancelled:
            proc.returncode = 1

    with pytest.raises(RuntimeError, match="past start"):
        list(executor.run("echo hi", on_start=on_start))
    assert events == ["job", "on_start"] + ([] if cancelled else ["resume"])


def test_windows_executor_starts_process_suspended_until_job_setup(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "_LINUX", False)
    flags = []

    class Process:
        pid = 1234
        stdout = None

        def poll(self):
            return None

        def wait(self, timeout=None):
            return 1

    process = Process()
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(executor, "resolve_bash", lambda: "bash.exe")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 1.0))
    monkeypatch.setattr(executor.subprocess, "Popen", lambda args, **kwargs: flags.append(kwargs["creationflags"]) or process)
    monkeypatch.setattr(executor, "_create_windows_job", lambda *args: (_ for _ in ()).throw(RuntimeError("stop after process creation")))
    monkeypatch.setattr(executor, "_terminate", lambda *args: None)
    monkeypatch.setattr(executor, "_close_windows_job", lambda *args: None)

    with pytest.raises(RuntimeError, match="stop after process creation"):
        list(executor.run("echo hi"))

    assert flags[0] & 0x00000004


def test_windows_job_close_waits_for_inflight_termination(monkeypatch):
    monkeypatch.setattr(executor, "_LINUX", False)
    entered = threading.Event()
    release = threading.Event()
    closed = threading.Event()
    events = []

    def terminate(job, code):
        events.append("terminate-start")
        entered.set()
        assert release.wait(2)
        events.append("terminate-end")
        return 1

    def close(handle):
        events.append("close")
        closed.set()

    kernel32 = SimpleNamespace(TerminateJobObject=Mock(side_effect=terminate), CloseHandle=Mock(side_effect=close))
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel32, raising=False)
    monkeypatch.setattr(executor, "_WINDOWS_JOBS", {1234: 5678})
    monkeypatch.setattr(executor.psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 1.0, children=lambda recursive=False: [], kill=lambda: None))
    process = SimpleNamespace(pid=1234)
    terminator = threading.Thread(target=executor._terminate, args=(process, 1.0))
    closer = threading.Thread(target=executor._close_windows_job, args=(process, 5678))
    terminator.start()
    try:
        assert entered.wait(1)
        closer.start()
        assert not closed.wait(0.05)
    finally:
        release.set()
        terminator.join(2)
        if closer.ident is not None:
            closer.join(2)

    assert events == ["terminate-start", "terminate-end", "close"]


def test_close_windows_job_keeps_handle_until_active_process_exits(monkeypatch):
    active_processes = [1]
    closed = threading.Event()

    def query(job, info_class, info, size, returned):
        info._obj.ActiveProcesses = active_processes[0]
        return 1

    kernel32 = SimpleNamespace(
        QueryInformationJobObject=Mock(side_effect=query),
        CloseHandle=Mock(side_effect=lambda handle: closed.set()),
    )
    monkeypatch.setattr(executor, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel32, raising=False)
    monkeypatch.setattr(executor, "_WINDOWS_JOBS", {1234: 5678})
    process = SimpleNamespace(pid=1234)

    executor._close_windows_job(process, 5678, keep_active=True)

    assert executor._WINDOWS_JOBS == {1234: 5678}
    active_processes[0] = 0
    assert closed.wait(1)
    assert executor._WINDOWS_JOBS == {}
