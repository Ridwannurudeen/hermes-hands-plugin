import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from hermeshands_device import executor

POSIX = pytest.mark.skipif(os.name == "nt", reason="POSIX process groups")
DEVICE_ROOT = str(Path(executor.__file__).parents[1])


@pytest.fixture
def groups(monkeypatch):
    sent = []
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {})
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", SimpleNamespace())
    monkeypatch.setattr(executor, "_send_to_posix_guardian", lambda line, deadline=None: sent.append(line))
    return sent


def _fake_processes(monkeypatch, create_times):
    monkeypatch.setattr(executor, "_LINUX", False)
    def process(pid):
        if pid not in create_times:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(create_time=lambda: create_times[pid])

    monkeypatch.setattr(executor.psutil, "Process", process)
    monkeypatch.setattr(executor.os, "getpgid", lambda pid: 100 if pid == 101 else pid, raising=False)
    monkeypatch.setattr(executor.psutil, "process_iter", lambda: [SimpleNamespace(pid=pid, create_time=lambda pid=pid: create_times[pid]) for pid in create_times])


def test_stop_kills_the_group_of_a_finished_job_and_skips_a_reused_id(monkeypatch, groups):
    live_groups = {100, 200}
    killed = []

    def killpg(pgid, sig):
        if pgid not in live_groups:
            raise ProcessLookupError(pgid)
        if sig:
            killed.append(pgid)

    monkeypatch.setattr(executor.os, "killpg", killpg, raising=False)
    monkeypatch.setattr(executor.os, "name", "posix")
    identities = {100: 1.0, 101: 1.5, 200: 9.0}
    _fake_processes(monkeypatch, identities)
    executor._track_posix_group(100, 1.0)
    identities.pop(100)
    executor._track_posix_group(200, 2.0)

    executor._terminate_posix_groups()

    assert killed == [100]
    assert executor._POSIX_GROUPS == {}
    assert groups == ["add 100 1.0\n", "checkall 0\n", "add 200 2.0\n", "killall 0\n"]


def test_tracking_a_new_group_drops_groups_that_are_already_empty(monkeypatch, groups):
    def killpg(pgid, sig):
        if pgid == 100:
            raise ProcessLookupError(pgid)

    monkeypatch.setattr(executor.os, "killpg", killpg, raising=False)
    monkeypatch.setattr(executor.os, "name", "posix")
    _fake_processes(monkeypatch, {})
    executor._track_posix_group(100, 1.0)
    executor._track_posix_group(300, 3.0)

    assert executor._POSIX_GROUPS == {300: 3.0}
    assert groups == ["add 100 1.0\n", "checkall 0\n", "del 100\n", "add 300 3.0\n"]


def test_windows_stop_leaves_posix_groups_alone(monkeypatch, groups):
    monkeypatch.setattr(executor.os, "name", "nt")
    executor._POSIX_GROUPS[100] = 1.0
    executor._terminate_posix_groups()
    assert executor._POSIX_GROUPS == {100: 1.0}
    assert groups == []


def _bash():
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")
    return bash


def _wait_for(path, timeout=10):
    deadline = time.monotonic() + timeout
    while not path.exists() or not path.read_text(encoding="utf-8-sig").strip():
        assert time.monotonic() < deadline, f"timed out waiting for {path}"
        time.sleep(0.02)
    return int(path.read_text(encoding="utf-8-sig").strip())


def _gone(pid, timeout=5):
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return True
    _, alive = psutil.wait_procs([process], timeout=timeout)
    return not [proc for proc in alive if proc.status() != psutil.STATUS_ZOMBIE]


def _hermes_background(tmp_path, command):
    log, pid_file = tmp_path / "bg.log", tmp_path / "bg.pid"
    return (
        f"( nohup bash -lc '{command}' > {log} 2>&1; rc=$?; printf '%s' $rc > {tmp_path / 'bg.exit'} ) & "
        f"echo $! > {pid_file} && cat {pid_file}"
    ), pid_file


@POSIX
def test_hermes_background_job_is_killed_when_the_session_stops(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "resolve_bash", _bash)
    marker = tmp_path / "sleep.pid"
    script, _ = _hermes_background(tmp_path, f"echo $$ > {marker}; exec sleep 120")
    output = b"".join(executor.run(script, timeout=15))
    assert output.strip().isdigit()
    sleeper = _wait_for(marker)
    assert psutil.pid_exists(sleeper)

    executor._terminate_posix_groups()

    assert _gone(sleeper)


def _host(tmp_path, body):
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {DEVICE_ROOT!r})\n"
        "from hermeshands_device import executor\n"
        f"executor.Path.home = lambda: Path({str(tmp_path)!r})\n"
        f"executor.resolve_bash = lambda: {shutil.which('bash')!r}\n"
        + body
    )
    return subprocess.Popen([sys.executable, "-u", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)


@POSIX
@pytest.mark.parametrize("how", ["background", "running"])
def test_killing_the_agent_kills_its_job_groups(tmp_path, how):
    _bash()
    marker = tmp_path / "sleep.pid"
    if how == "background":
        script, _ = _hermes_background(tmp_path, f"echo $$ > {marker}; exec sleep 120")
        body = f"list(executor.run({script!r}, timeout=30))\nimport time\ntime.sleep(60)\n"
    else:
        body = f"list(executor.run({f'sleep 120 & echo $! > {marker}; wait'!r}, timeout=60))\n"
    host = _host(tmp_path, body)
    sleeper = None
    try:
        sleeper = _wait_for(marker)
        time.sleep(0.3)
        assert host.poll() is None, host.communicate(timeout=1)
        os.kill(host.pid, getattr(signal, "SIGKILL"))
        host.wait(timeout=5)
        assert _gone(sleeper), "the job outlived the agent"
    finally:
        if host.poll() is None:
            host.kill()
        host.communicate(timeout=5)
        if sleeper is not None and psutil.pid_exists(sleeper):
            os.kill(sleeper, getattr(signal, "SIGKILL"))


@POSIX
@pytest.mark.parametrize("terminal_gone", [False, True])
def test_closing_the_witness_window_stops_the_session_and_its_command(tmp_path, terminal_gone):
    _bash()
    marker = tmp_path / "sleep.pid"
    closed = tmp_path / "terminal-closed"
    body = (
        "import httpx, json, threading, time\n"
        "from hermeshands_device import config, loop\n"
        f"root = Path({str(tmp_path / '.hermes-hands')!r})\n"
        "config.ROOT, config.CONFIG_PATH, config.POLICY_PATH, config.KEY_PATH = root, root / 'c.json', root / 'p.json', root / 'd.json'\n"
        "loop.Path.home = executor.Path.home\n"
        "loop.executor.reap_recorded_processes = lambda: None\n"
        "class Console:\n"
        "    def write(self, text):\n"
        f"        if Path({str(closed)!r}).exists():\n"
        "            raise OSError(5, 'Input/output error')\n"
        "        print(text, end='', flush=True)\n"
        "    def read_line(self, prompt):\n"
        "        threading.Event().wait()\n"
        "agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204)), console=Console())\n"
        "agent.witness, agent.session_state = True, 'active'\n"
        "agent._heartbeat_loop = lambda: None\n"
        "agent._request_session_screenshot_consent = lambda: None\n"
        "agent._post = lambda endpoint, body: time.sleep(0.1) or httpx.Response(204)\n"
        "jobs = [{'job_id': 'job1', 'type': 'exec', 'script': " + repr(f"sleep 120 & echo $! > {marker}; wait") + "}]\n"
        "agent._verify_response = lambda response, endpoint: jobs.pop() if endpoint == '/device/poll' and jobs else {}\n"
        "agent.accepted_policy_hash = loop.policy.digest()\n"
        "agent.run_forever()\n"
    )
    host = _host(tmp_path, body)
    sleeper = None
    try:
        sleeper = _wait_for(marker)
        assert host.poll() is None, host.communicate(timeout=1)
        if terminal_gone:
            closed.write_text("x", encoding="utf-8")
        os.kill(host.pid, getattr(signal, "SIGHUP"))
        out, err = host.communicate(timeout=15)
        assert _gone(sleeper), "the command outlived the closed window"
        receipts = list((tmp_path / ".hermes-hands" / "receipts").glob("*.json"))
        assert len(receipts) == 1, (out, err)
        saved = json.loads(receipts[0].read_text(encoding="utf-8-sig"))["payload"]
        assert saved["end_reason"] == "stopped_by_person"
        assert saved["shutdown_delivery"] == "confirmed"
        outcomes = [event["outcome"] for event in saved["events"] if event["label"] == "Running a command"]
        assert outcomes[-1] == "Stopped because you stopped the session"
        if not terminal_gone:
            assert b"Session stopped. Nothing else will run on this computer." in out
    finally:
        if host.poll() is None:
            host.kill()
            host.communicate(timeout=5)
        if sleeper is not None and psutil.pid_exists(sleeper):
            os.kill(sleeper, getattr(signal, "SIGKILL"))
