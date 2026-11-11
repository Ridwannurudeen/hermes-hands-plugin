import os
import signal
import subprocess
import time

import psutil
import pytest

from hermeshands_device import executor

from test_lane_f2_posix import _bash, _gone, _wait_for

LINUX = pytest.mark.skipif(
    not executor.sys.platform.startswith("linux"), reason="Linux process groups and /proc"
)


@LINUX
def test_twenty_background_jobs_do_not_break_the_next_command(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "resolve_bash", _bash)
    monkeypatch.setattr(executor.Path, "home", lambda: tmp_path)
    fillers = [subprocess.Popen(["sleep", "300"]) for _ in range(max(0, 450 - len(psutil.pids())))]
    sleepers = []
    try:
        for index in range(20):
            marker = tmp_path / f"bg{index}.pid"
            assert (
                b"".join(
                    executor.run(
                        f"sleep 300 >/dev/null 2>&1 & echo $! > {marker}; echo {index}", timeout=15
                    )
                )
                == f"{index}\n".encode()
            )
            sleepers.append(_wait_for(marker))
        started = time.monotonic()
        codes = []
        assert b"".join(executor.run("echo done", timeout=15, on_exit=codes.append)) == b"done\n"
        assert codes == [0]
        assert time.monotonic() - started < 1.5
        assert all(psutil.pid_exists(pid) for pid in sleepers), (
            "an earlier background job was killed"
        )
        executor._terminate_posix_groups()
        assert all(_gone(pid, timeout=2) for pid in sleepers), "Stop left a background job running"
    finally:
        for filler in fillers:
            filler.kill()
            filler.wait()
        for pid in sleepers:
            if psutil.pid_exists(pid):
                os.kill(pid, getattr(signal, "SIGKILL"))


@LINUX
def test_a_stalled_guardian_fails_the_new_job_and_keeps_earlier_jobs(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "resolve_bash", _bash)
    monkeypatch.setattr(executor.Path, "home", lambda: tmp_path)
    sleepers = []
    stalled = None
    try:
        for index in range(2):
            marker = tmp_path / f"bg{index}.pid"
            assert b"".join(executor.run(f"sleep 300 >/dev/null 2>&1 & echo $! > {marker}; echo {index}", timeout=15)) == f"{index}\n".encode()
            sleepers.append(_wait_for(marker))
        groups = dict(executor._POSIX_GROUPS)
        stalled = executor._POSIX_GUARDIAN.pid
        os.kill(stalled, getattr(signal, "SIGSTOP"))
        with pytest.raises(RuntimeError, match="Could not establish job guardian protection"):
            list(executor.run("echo late", timeout=15))
        assert all(psutil.pid_exists(pid) for pid in sleepers), "a check timeout killed earlier jobs"
        assert executor._POSIX_GROUPS == groups
        assert b"".join(executor.run("echo next", timeout=15)) == b"next\n"
        assert executor._POSIX_GUARDIAN.pid != stalled
        assert all(psutil.pid_exists(pid) for pid in sleepers)
        executor._terminate_posix_groups()
        assert all(_gone(pid, timeout=2) for pid in sleepers), "Stop left a background job running"
    finally:
        if stalled is not None and psutil.pid_exists(stalled):
            os.kill(stalled, getattr(signal, "SIGKILL"))
        for pid in sleepers:
            if psutil.pid_exists(pid):
                os.kill(pid, getattr(signal, "SIGKILL"))
