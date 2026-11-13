import os
import signal
import time

import psutil
import pytest

from hermeshands_device import executor

from test_lane_f2_posix import _bash, _gone, _host, _wait_for

POSIX = pytest.mark.skipif(os.name == "nt", reason="POSIX process groups and signals")


@POSIX
def test_a_producer_piped_into_head_dies_of_sigpipe(monkeypatch, tmp_path):
    monkeypatch.setattr(executor, "resolve_bash", _bash)
    monkeypatch.setattr(executor.Path, "home", lambda: tmp_path)
    started = time.monotonic()
    output = b"".join(
        executor.run(
            'yes | head -1; echo "${PIPESTATUS[@]}"; while :; do echo y; done | head -1', timeout=20
        )
    )
    assert output == b"y\n141 0\ny\n"
    assert time.monotonic() - started < 10


def _detached_sleep(marker, shape="nohup"):
    if shape == "subshell":
        return f"( nohup bash -c 'echo $$ > {marker}; exec sleep 300' > /dev/null 2>&1 ) & echo started"
    return f"nohup sleep 300 >/dev/null 2>&1 & echo $! > {marker}; echo started"


@POSIX
@pytest.mark.parametrize("shape", ["nohup", "subshell"])
def test_stop_kills_a_background_child_after_its_command_exited(monkeypatch, tmp_path, shape):
    monkeypatch.setattr(executor, "resolve_bash", _bash)
    monkeypatch.setattr(executor.Path, "home", lambda: tmp_path)
    survivors = []
    for attempt in range(20):
        marker = tmp_path / f"sleep-{attempt}.pid"
        assert b"".join(executor.run(_detached_sleep(marker, shape), timeout=15)) == b"started\n"
        sleeper = _wait_for(marker)
        executor._terminate_posix_groups()
        if not _gone(sleeper, timeout=2):
            survivors.append(sleeper)
            os.kill(sleeper, getattr(signal, "SIGKILL"))
    assert survivors == []


@POSIX
def test_killing_the_agent_kills_a_background_child_of_a_finished_command(tmp_path):
    _bash()
    marker = tmp_path / "sleep.pid"
    body = f"list(executor.run({_detached_sleep(marker)!r}, timeout=30))\nimport time\ntime.sleep(60)\n"
    host = _host(tmp_path, body)
    sleeper = None
    try:
        sleeper = _wait_for(marker, host=host)
        time.sleep(0.5)
        assert host.poll() is None, host.communicate(timeout=1)
        os.kill(host.pid, getattr(signal, "SIGKILL"))
        host.wait(timeout=5)
        assert _gone(sleeper), "the background child outlived the agent"
    finally:
        if host.poll() is None:
            host.kill()
        host.communicate(timeout=5)
        if sleeper is not None and psutil.pid_exists(sleeper):
            os.kill(sleeper, getattr(signal, "SIGKILL"))


@POSIX
@pytest.mark.parametrize("shape", ["nohup", "subshell"])
def test_stopping_the_witness_session_kills_a_background_child_of_a_finished_command(tmp_path, shape):
    _bash()
    marker = tmp_path / "sleep.pid"
    done = tmp_path / "job-done"
    body = (
        "import httpx, threading, time\n"
        "from hermeshands_device import config, loop\n"
        f"root = Path({str(tmp_path / '.hermes-hands')!r})\n"
        "config.ROOT, config.CONFIG_PATH, config.POLICY_PATH, config.KEY_PATH = root, root / 'c.json', root / 'p.json', root / 'd.json'\n"
        "loop.Path.home = executor.Path.home\n"
        "loop.executor.reap_recorded_processes = lambda: None\n"
        "class Console:\n"
        "    def write(self, text):\n"
        "        print(text, end='', flush=True)\n"
        "    def read_line(self, prompt):\n"
        "        threading.Event().wait()\n"
        "agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204)), console=Console())\n"
        "agent.witness, agent.session_state = True, 'active'\n"
        "agent._heartbeat_loop = lambda: None\n"
        "agent._request_session_screenshot_consent = lambda: None\n"
        "def post(endpoint, body):\n"
        "    if endpoint == '/device/result' and body.get('done'):\n"
        f"        Path({str(done)!r}).with_suffix('.tmp').write_text(str(body.get('error')) + ' (returncode=' + str(body.get('returncode')) + ')', encoding='utf-8')\n"
        f"        Path({str(done)!r}).with_suffix('.tmp').replace({str(done)!r})\n"
        "    return httpx.Response(204)\n"
        "agent._post = post\n"
        "jobs = [{'job_id': 'job1', 'type': 'exec', 'script': " + repr(_detached_sleep(marker, shape)) + "}]\n"
        "agent._verify_response = lambda response, endpoint: jobs.pop() if endpoint == '/device/poll' and jobs else {}\n"
        "agent.accepted_policy_hash = loop.policy.digest()\n"
        "agent.run_forever()\n"
    )
    host = _host(tmp_path, body)
    sleeper = None
    try:
        deadline = time.monotonic() + 30
        while not done.exists():
            if host.poll() is not None or time.monotonic() >= deadline:
                if host.poll() is None:
                    host.kill()
                raise AssertionError(f"no job result from the agent: {host.communicate(timeout=5)}")
            time.sleep(0.02)
        result = done.read_text(encoding="utf-8-sig")
        assert result == "None (returncode=0)", f"the device refused or failed the job: {result!r}"
        sleeper = _wait_for(marker, host=host)
        os.kill(host.pid, getattr(signal, "SIGHUP"))
        out, err = host.communicate(timeout=15)
        assert b"Session stopped. Nothing else will run on this computer." in out, (out, err)
        assert _gone(sleeper), "the background child outlived the stopped session"
    finally:
        if host.poll() is None:
            host.kill()
            host.communicate(timeout=5)
        if sleeper is not None and psutil.pid_exists(sleeper):
            os.kill(sleeper, getattr(signal, "SIGKILL"))
