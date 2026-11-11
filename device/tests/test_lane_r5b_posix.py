import os
import signal
import threading
import time

import psutil
import pytest

from hermeshands_device import executor

from test_lane_f2_posix import _bash, _gone, _host, _wait_for

LINUX = pytest.mark.skipif(not executor.sys.platform.startswith("linux"), reason="Linux process groups and /proc")


def _late_child(marker, shape):
    if shape == "late_nohup":
        return f"nohup bash -c 'sleep 0.4; sleep 300 >/dev/null 2>&1 & echo $! > {marker}; exit 0' >/dev/null 2>&1 & echo x"
    return f"( sleep 0.4; sleep 300 >/dev/null 2>&1 & echo $! > {marker} ) >/dev/null 2>&1 & echo x"


def _kill(pid):
    if pid is not None and psutil.pid_exists(pid):
        os.kill(pid, getattr(signal, "SIGKILL"))


@pytest.fixture
def jobs(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "resolve_bash", _bash)
    monkeypatch.setattr(executor.Path, "home", lambda: tmp_path)
    return tmp_path


@LINUX
@pytest.mark.parametrize("shape", ["late_fork", "late_nohup"])
def test_stop_kills_a_child_started_after_its_starter_was_recorded(jobs, shape):
    marker = jobs / "late.pid"
    sleeper = None
    try:
        assert b"".join(executor.run(_late_child(marker, shape), timeout=15)) == b"x\n"
        sleeper = _wait_for(marker)
        time.sleep(0.3)
        assert os.getpgid(sleeper) == os.getsid(sleeper)
        executor._terminate_posix_groups()
        assert _gone(sleeper, timeout=2), "the late background child outlived Stop"
    finally:
        _kill(sleeper)


@LINUX
@pytest.mark.parametrize("shape", ["late_fork", "late_nohup"])
def test_agent_death_kills_a_child_started_after_its_starter_was_recorded(tmp_path, shape):
    _bash()
    marker = tmp_path / "late.pid"
    body = f"list(executor.run({_late_child(marker, shape)!r}, timeout=30))\nimport time\ntime.sleep(60)\n"
    host = _host(tmp_path, body)
    sleeper = None
    try:
        sleeper = _wait_for(marker)
        time.sleep(0.3)
        assert host.poll() is None, host.communicate(timeout=1)
        os.kill(host.pid, getattr(signal, "SIGKILL"))
        host.wait(timeout=5)
        assert _gone(sleeper), "the late background child outlived the agent"
    finally:
        if host.poll() is None:
            host.kill()
        host.communicate(timeout=5)
        _kill(sleeper)


def _wall_clock_step(monkeypatch, seconds=1.0):
    actual = psutil.Process.create_time
    monkeypatch.setattr(psutil.Process, "create_time", lambda self: actual(self) + seconds)


@LINUX
def test_a_timeout_kills_the_whole_group_after_a_wall_clock_step(jobs, monkeypatch):
    marker = jobs / "sleep.pid"
    sleeper = None
    try:
        output = b"".join(executor.run(f"sleep 301 & echo $! > {marker}; sleep 300", timeout=2, on_start=lambda proc, created: _wall_clock_step(monkeypatch)))
        assert output.endswith(b"[device timeout]\n")
        sleeper = _wait_for(marker)
        assert _gone(sleeper, timeout=2), "the background child outlived the timeout after a clock step"
    finally:
        _kill(sleeper)


@LINUX
def test_stop_kills_a_finished_jobs_group_after_a_wall_clock_step_without_the_guardian(jobs, monkeypatch):
    marker = jobs / "sleep.pid"
    sleeper = None
    try:
        assert b"".join(executor.run(f"sleep 300 >/dev/null 2>&1 & echo $! > {marker}; echo started", timeout=15)) == b"started\n"
        sleeper = _wait_for(marker)
        _wall_clock_step(monkeypatch)
        sent = []
        monkeypatch.setattr(executor, "_send_to_posix_guardian", lambda line, deadline=None: sent.append(line))
        executor._terminate_posix_groups()
        assert sent == ["killall 0\n"]
        assert _gone(sleeper, timeout=2), "Stop skipped a running group after a clock step"
    finally:
        _kill(sleeper)


def _guardian_pid():
    with executor._POSIX_GROUPS_LOCK:
        executor._send_to_posix_guardian("")
        return executor._POSIX_GUARDIAN.pid


def _run_ok(script="echo hi; exit 3"):
    codes = []
    started = time.monotonic()
    output = b"".join(executor.run(script, timeout=15, on_exit=codes.append))
    return output, codes, time.monotonic() - started


@LINUX
def test_a_killed_guardian_does_not_block_later_commands(jobs):
    assert _run_ok()[:2] == (b"hi\n", [3])
    guardian = _guardian_pid()
    os.kill(guardian, getattr(signal, "SIGKILL"))
    assert _gone(guardian)
    for _ in range(3):
        assert _run_ok()[:2] == (b"hi\n", [3])
    assert _guardian_pid() != guardian


@LINUX
def test_a_failed_update_at_exit_does_not_block_later_commands(jobs, caplog):
    marker = jobs / "sleep.pid"
    guardian = _guardian_pid()
    stopper = threading.Timer(0.5, os.kill, (guardian, getattr(signal, "SIGSTOP")))
    stopper.start()
    sleeper = None
    try:
        assert _run_ok(f"sleep 300 >/dev/null 2>&1 & echo $! > {marker}; sleep 1; echo hi")[:2] == (b"hi\n", [0])
        sleeper = _wait_for(marker)
        assert any("Could not update job guardian" in record.getMessage() for record in caplog.records)
        assert _gone(sleeper), "the unprotected background child was left running"
        for _ in range(2):
            assert _run_ok()[:2] == (b"hi\n", [3])
    finally:
        stopper.cancel()
        stale = executor._POSIX_GUARDIAN
        if stale is not None and stale.pid == guardian and stale.poll() is None:
            stale.kill()
            stale.wait()
        _kill(sleeper)


@LINUX
def test_a_normal_command_starts_and_finishes_with_its_return_code(jobs):
    for _ in range(50):
        output, codes, elapsed = _run_ok()
        assert (output, codes) == (b"hi\n", [3])
        assert elapsed < 5


@LINUX
def test_start_ticks_parse_a_command_name_with_spaces_and_parentheses(tmp_path):
    odd = tmp_path / "a) b (c"
    odd.symlink_to("/bin/sleep")

    def uptime_ticks():
        with open("/proc/uptime", encoding="ascii") as uptime:
            return float(uptime.read().split()[0]) * os.sysconf("SC_CLK_TCK")

    before = uptime_ticks()
    process = executor.subprocess.Popen([str(odd), "30"])
    try:
        ticks = executor._start_time(process.pid)
        after = uptime_ticks()
        assert psutil.Process(process.pid).name() == "a) b (c"
        assert before - 2 <= ticks <= after + 2
        assert executor._start_time(process.pid) == ticks
    finally:
        process.kill()
        process.wait()
