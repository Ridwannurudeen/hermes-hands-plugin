import inspect
import json
import os
import queue
import re
import shlex
import threading
import time
from typing import get_type_hints

import httpx
import psutil
import pytest

from hermeshands_device import cli, loop, config
from hermeshands_device.protocol import D2R, R2D, b64u, canonical_json, generate_keypair, sign_request, verify_request


def _core_wrapped(command):
    try:
        from tools.environments.base_session_env import _wrap_command_script
    except ImportError:
        escaped = command.replace("'", "'\\''")
        escaped += '\n\n__hermes_rc=$? __hermes_ps=("${PIPESTATUS[@]}"); (exit $__hermes_rc) && :'
        return f"eval '{escaped}'"
    return _wrap_command_script(
        command,
        quoted_cwd="/tmp",
        quoted_snap="/tmp/snapshot",
        snap_tmp_template="/tmp/snapshot.tmp.XXXXXXXXXX",
        passthrough_names=(),
        snapshot_ready=False,
        cwd_marker="__CWD__",
        pipe_marker="__PIPE__",
    )


def _signed_poll(monkeypatch, *, body=None, signature_body=None, response_ts=None, response_nonce=None, signing_key=None):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    payload = {"job_id": "job-1", "type": "exec", "script": "echo signed"}
    body = canonical_json(payload) if body is None else body
    signature_body = body if signature_body is None else signature_body
    ts = int(time.time()) if response_ts is None else response_ts
    key = private if signing_key is None else signing_key

    def handler(request):
        nonce = request.headers["X-Hands-Nonce"] if response_nonce is None else response_nonce
        path = "/api/plugins/hermes-hands/device/poll"
        return httpx.Response(200, content=body, request=request, headers={
            "X-Hands-Ts": str(ts), "X-Hands-Nonce": nonce,
            "X-Hands-Signature": sign_request(key, R2D, ts, nonce, "POST", path, signature_body),
        })

    return payload, loop.DeviceLoop(transport=httpx.MockTransport(handler))


def test_loop_accepts_correctly_signed_poll_reply(monkeypatch):
    job, agent = _signed_poll(monkeypatch)
    try:
        assert agent._verify_response(agent._post("/device/poll", {"wait": 25, "policy_hash": "hash"}), "/device/poll") == job
    finally:
        agent.client.close()


def test_verified_poll_accepts_sent_policy_hash_before_job(monkeypatch):
    job, agent = _signed_poll(monkeypatch)
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("accepted-hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter(()))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    try:
        poll_body = agent._poll_body()
        assert poll_body["policy_hash"] == "accepted-hash"
        assert agent._verify_response(agent._post("/device/poll", poll_body), "/device/poll") == job
        assert agent.accepted_policy_hash == "accepted-hash"
        agent._run_job(job)
        assert posted == [{"chunk": "", "done": True, "returncode": 0}]
    finally:
        agent.client.close()


def test_loop_rejects_tampered_poll_body(monkeypatch):
    body = canonical_json({"job_id": "job-1", "type": "exec", "script": "echo altered"})
    signature_body = canonical_json({"job_id": "job-1", "type": "exec", "script": "echo signed"})
    _, agent = _signed_poll(monkeypatch, body=body, signature_body=signature_body)
    try:
        try:
            agent._verify_response(agent._post("/device/poll", {"wait": 25}), "/device/poll")
        except PermissionError:
            pass
        else:
            raise AssertionError("tampered body accepted")
    finally:
        agent.client.close()


def test_loop_rejects_stale_poll_reply(monkeypatch):
    _, agent = _signed_poll(monkeypatch, response_ts=int(time.time()) - 301)
    try:
        try:
            agent._verify_response(agent._post("/device/poll", {"wait": 25}), "/device/poll")
        except PermissionError:
            pass
        else:
            raise AssertionError("stale reply accepted")
    finally:
        agent.client.close()


def test_loop_rejects_poll_reply_signed_by_wrong_key(monkeypatch):
    wrong_private, _ = generate_keypair()
    _, agent = _signed_poll(monkeypatch, signing_key=wrong_private)
    try:
        try:
            agent._verify_response(agent._post("/device/poll", {"wait": 25}), "/device/poll")
        except PermissionError:
            pass
        else:
            raise AssertionError("reply signed by the wrong key accepted")
    finally:
        agent.client.close()


@pytest.mark.parametrize("status,error", [(401, "unknown_device"), (409, "policy_changed")])
@pytest.mark.parametrize("mutation", ["wrong_key", "wrong_nonce", "unsigned"])
def test_control_error_replies_reject_signature_mutants(monkeypatch, status, error, mutation):
    private, public = generate_keypair()
    wrong_private, _ = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)))
    request = httpx.Request("POST", "https://example.test/device/poll", headers={"X-Hands-Nonce": "request-nonce"})
    body = canonical_json({"error": error})
    timestamp = int(time.time())
    response_nonce = "other-nonce" if mutation == "wrong_nonce" else "request-nonce"
    key = wrong_private if mutation == "wrong_key" else private
    headers = {}
    if mutation != "unsigned":
        headers = {
            "X-Hands-Ts": str(timestamp),
            "X-Hands-Nonce": response_nonce,
            "X-Hands-Signature": sign_request(key, R2D, timestamp, response_nonce, "POST", "/api/plugins/hermes-hands/device/poll", body),
        }
    response = httpx.Response(status, content=body, request=request, headers=headers)
    try:
        with pytest.raises(ValueError, match=f"transient relay status {status}"):
            agent._verify_response(response, "/device/poll")
        assert not agent.stop_event.is_set()
    finally:
        agent.client.close()


def test_device_loop_client_ignores_environment_proxies(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9999")
    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)))
    try:
        assert agent.client._trust_env is False
    finally:
        agent.client.close()


def test_device_loop_constructor_keeps_frozen_console_seam(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    console = object()

    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)), console=console)
    try:
        signature = inspect.signature(loop.DeviceLoop)
        assert tuple(signature.parameters) == ("allow_screen", "transport", "console")
        assert all(parameter.kind is inspect.Parameter.KEYWORD_ONLY for parameter in signature.parameters.values())
        assert get_type_hints(loop.DeviceLoop.__init__)["transport"] == httpx.BaseTransport | None
        assert get_type_hints(loop.DeviceLoop.__init__)["console"] == loop.ConsoleInput | None
        assert agent.console is console
    finally:
        agent.client.close()


def test_final_device_result_always_sends_returncode_and_error(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    bodies = []
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: bodies.append(body) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})

    agent._result("final", 0, done=True, returncode=0)

    assert bodies == [{
        "job_id": "final",
        "seq": 0,
        "chunk": "",
        "done": True,
        "policy_hash": "hash",
        "returncode": 0,
        "error": None,
    }]


def test_screenshot_final_result_has_success_code(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.allow_screen = True
    agent.stop_event = threading.Event()
    agent.process_lock = threading.Lock()
    agent.running = {}
    agent.processes = {}
    agent.job_start_events = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    bodies = []
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: b"png")
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: bodies.append(body) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})

    agent._run_job({"job_id": "screen", "type": "screenshot"})

    assert bodies == [{
        "job_id": "screen",
        "seq": 0,
        "chunk": "",
        "done": True,
        "policy_hash": "hash",
        "returncode": 0,
        "error": None,
        "png_b64": "cG5n",
    }]


class PromptOwner:
    def __init__(self, answers):
        self.answers = iter(answers)
        self.requests = []

    def request(self, prompt_id, text, *, timeout=None):
        self.requests.append((prompt_id, text, timeout))
        return next(self.answers)


def _screenshot_agent(owner):
    agent = object.__new__(loop.DeviceLoop)
    agent.allow_screen = True
    agent.console_owner = owner
    agent.instance = "witness-instance"
    agent.witness = True
    agent.session_state = "active"
    agent.session_deadline = None
    agent.stop_event = threading.Event()
    agent._stop_lock = threading.Lock()
    agent.stop_reason = None
    agent.stop_flush_deadline = None
    agent.process_lock = threading.Lock()
    agent.running = {}
    agent.processes = {}
    agent.job_start_events = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    return agent


@pytest.mark.parametrize("answer", ["Y", "y"])
def test_each_screenshot_request_requires_its_own_consent(monkeypatch, answer):
    owner = PromptOwner([answer, "N"])
    agent = _screenshot_agent(owner)
    captures, posted = [], []
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: captures.append(kwargs) or b"png")
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append((job_id, kwargs)))

    agent._run_job({"job_id": "screen-one", "type": "screenshot"})
    agent._run_job({"job_id": "screen-two", "type": "screenshot"})

    assert owner.requests == [
        ("witness-instance-screenshot-screen-one", "Allow this screenshot?", 30),
        ("witness-instance-screenshot-screen-two", "Allow this screenshot?", 30),
    ]
    assert captures == [{"allow_screen": True}]
    assert posted == [
        ("screen-one", {"done": True, "returncode": 0, "png": b"png"}),
        ("screen-two", {"done": True, "returncode": 126, "error": "screenshot_declined"}),
    ]


@pytest.mark.parametrize("answer", [None, "", "n", "N", "yes", "ok"])
def test_screenshot_timeout_eof_and_non_y_decline(monkeypatch, answer):
    owner = PromptOwner([answer])
    agent = _screenshot_agent(owner)
    posted = []
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: pytest.fail("declined screenshot was captured"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._run_job({"job_id": "screen", "type": "screenshot"})

    assert owner.requests == [("witness-instance-screenshot-screen", "Allow this screenshot?", 30)]
    assert posted == [{"done": True, "returncode": 126, "error": "screenshot_declined"}]


def test_stop_during_screenshot_prompt_returns_stopped_result(monkeypatch):
    owner = PromptOwner([None])
    agent = _screenshot_agent(owner)
    posted = []

    def stop_prompt(*args, **kwargs):
        agent._begin_stopping()
        return None

    owner.request = stop_prompt
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: pytest.fail("stopped screenshot was captured"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._run_job({"job_id": "screen", "type": "screenshot"})

    assert posted == [{"done": True, "returncode": 130, "error": "stopped_by_person"}]


def test_expired_witness_deadline_refuses_a_new_job(monkeypatch):
    agent = _screenshot_agent(PromptOwner([]))
    agent.session_deadline = time.monotonic() - 1
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    monkeypatch.setattr(loop.policy, "snapshot", lambda: pytest.fail("expired session checked policy"))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("expired session ran job"))

    agent._run_job({"job_id": "late", "type": "exec", "script": "echo too late"})

    assert agent.session_state == "stopping"
    assert agent.stop_reason == "session_timeout"
    assert posted == [{"done": True, "returncode": 124, "error": "session_timeout"}]


def test_witness_deadline_wakes_after_poll_and_refuses_late_job(monkeypatch, tmp_path):
    _, agent = _signed_poll(monkeypatch)
    monkeypatch.setattr(loop.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    agent.witness = True
    agent.session_state = "active"
    clock = type("Clock", (), {"monotonic": lambda self: self.now})()
    clock.now = 100.0
    monkeypatch.setattr(loop, "time", clock)
    monkeypatch.setattr(agent, "_heartbeat_loop", lambda: None)
    monkeypatch.setattr(agent, "_request_session_screenshot_consent", lambda: None)
    monkeypatch.setattr(agent, "_cancel_running_jobs", lambda: None)
    launched = []
    monkeypatch.setattr(agent, "_run_job", lambda job, start_event=None: launched.append(job))
    poll_calls = []

    def post(endpoint, body):
        if endpoint == "/device/poll":
            poll_calls.append(body)
            if len(poll_calls) == 1:
                clock.now += 1801
            else:
                agent.stop_event.set()
        return httpx.Response(200, request=httpx.Request("POST", "https://example.test"))

    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", lambda response, endpoint: {"job_id": "late", "type": "exec"})

    agent.run_forever()

    assert agent.session_deadline == 1900.0
    assert poll_calls
    assert launched == []
    assert agent.stop_reason == "session_timeout"
    assert agent.session_state == "stopped"


def test_witness_poll_timeout_cannot_outlive_session_deadline(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    agent.witness = True
    agent.session_state = "active"
    agent.session_deadline = 11.25
    clock = type("Clock", (), {"monotonic": lambda self: 10.0, "time": lambda self: 1000.0})()
    monkeypatch.setattr(loop, "time", clock)
    timeouts = []

    def handler(request):
        timeouts.append(request.extensions["timeout"])
        return httpx.Response(204, request=request)

    agent.client.close()
    agent.client = httpx.Client(transport=httpx.MockTransport(handler), timeout=35, trust_env=False)
    try:
        body = agent._poll_body()
        agent._post("/device/poll", body)
    finally:
        agent.client.close()

    assert body["wait"] == 1
    assert [max(timeout.values()) for timeout in timeouts] == [1.25]


def test_active_witness_poll_wait_fits_stop_flush_budget(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    agent.witness = True
    agent.session_state = "active"
    try:
        assert agent._poll_body()["wait"] <= 2
    finally:
        agent.client.close()


def test_console_stop_cancels_registered_process_tree(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    process = object()
    agent.witness = True
    agent.session_state = "active"
    agent.processes["long-job"] = (process, 123.0)
    terminated = []
    job_termination_calls = []
    monkeypatch.setattr(loop.executor, "_terminate", lambda proc, started: terminated.append((proc, started)))
    monkeypatch.setattr(loop.executor, "_terminate_windows_jobs", lambda: job_termination_calls.append(True))

    try:
        agent.console_owner.on_stop()

        assert agent.session_state == "stopping"
        assert agent.stop_event.is_set()
        assert terminated == [(process, 123.0)]
        assert job_termination_calls
    finally:
        agent.client.close()


@pytest.mark.parametrize(
    ("answer", "expected"),
    [("Y", True), ("y", True), ("N", False), ("n", False), ("", False), ("yes", False), ("ok", False)],
)
def test_session_screenshot_consent_requires_explicit_y(monkeypatch, answer, expected):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))

    class InputConsole:
        def __init__(self):
            self.lines = queue.Queue()
            self.outputs = []
            self.lines.put(answer)

        def write(self, text):
            self.outputs.append(text)

        def read_line(self, prompt):
            return self.lines.get()

    console = InputConsole()
    agent = loop.DeviceLoop(console=console)
    agent.witness = True
    agent.session_state = "active"
    consent = threading.Thread(target=agent._request_session_screenshot_consent)
    consent.start()
    consent.join(1)
    assert not consent.is_alive()

    agent.console_owner.close()
    console.lines.put(None)
    agent.console_owner.join(1)
    assert agent.allow_screen is expected


@pytest.mark.parametrize("answer", ["S", "s", None])
def test_stop_or_eof_during_session_screenshot_consent_stops_witness(monkeypatch, answer):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))

    class InputConsole:
        def __init__(self):
            self.lines = queue.Queue()
            self.lines.put(answer)

        def write(self, text):
            return None

        def read_line(self, prompt):
            return self.lines.get()

    console = InputConsole()
    agent = loop.DeviceLoop(console=console)
    agent.witness = True
    agent.session_state = "active"
    consent = threading.Thread(target=agent._request_session_screenshot_consent)
    consent.start()
    consent.join(1)

    agent.console_owner.close()
    agent.console_owner.join(1)
    assert not consent.is_alive()
    assert agent.stop_event.is_set()
    assert agent.witness is False


def test_poll_and_heartbeat_continue_while_console_prompt_is_open(monkeypatch, tmp_path):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(loop.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)

    class WaitingConsole:
        def __init__(self):
            self.read_started = threading.Event()
            self.prompt_displayed = threading.Event()
            self.lines = queue.Queue()
            self.outputs = []
            self.prompts = []

        def write(self, text):
            self.outputs.append(text)
            if "Allow screenshot requests this session?" in text:
                self.prompt_displayed.set()

        def read_line(self, prompt):
            self.prompts.append(prompt)
            self.read_started.set()
            if "Allow screenshot requests this session?" in prompt:
                self.prompt_displayed.set()
            return self.lines.get()

        def feed(self, line):
            self.lines.put(line)

    console = WaitingConsole()
    agent = loop.DeviceLoop(console=console, transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)))
    agent.witness = True
    agent.session_state = "active"
    agent.help_requests.put("please help")
    sent_help = []
    monkeypatch.setattr(agent, "_send_help_request", lambda text: sent_help.append(text) or True)
    counts = {"poll": 0, "heartbeat": 0}
    lock = threading.Lock()
    progress = threading.Event()
    prompt_open_at_progress = []

    def post(endpoint, body):
        assert console.prompt_displayed.wait(1)
        key = "poll" if endpoint == "/device/poll" else "heartbeat"
        with lock:
            counts[key] += 1
            if all(counts.values()):
                with agent.console_owner._lock:
                    prompt_open_at_progress.append(
                        agent.console_owner._read_prompt.prompt_id
                        if agent.console_owner._read_prompt is not None
                        else None
                    )
                progress.set()
                agent._begin_stopping()
        return httpx.Response(204)

    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    monkeypatch.setattr(agent, "_cancel_running_jobs", lambda: None)
    serve = threading.Thread(target=agent.run_forever)
    serve.start()

    try:
        assert console.prompt_displayed.wait(1)
        assert "Allow screenshot requests this session?" in console.prompts[0]
        assert progress.wait(1)
        serve.join(2)
        assert not serve.is_alive()
    finally:
        console.feed(None)
        agent.console_owner.join(1)

    assert counts["poll"] >= 1
    assert counts["heartbeat"] >= 1
    assert sent_help == ["please help"]
    assert prompt_open_at_progress
    assert set(prompt_open_at_progress) == {f"{agent.instance}-screenshot-session"}


def test_first_transient_auth_warning_is_not_suppressed(monkeypatch, caplog):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)))
    monkeypatch.setattr(loop.time, "monotonic", lambda: 10.0)
    try:
        agent._transient_status(401)
        agent._transient_status(401)
    finally:
        agent.client.close()
    warnings = [record.message for record in caplog.records if "Relay returned HTTP 401" in record.message]
    assert warnings == ["Relay returned HTTP 401; retrying. Check for clock skew over 300 seconds, a dashboard started without the relay seed, or a device revoked before this version."]


def test_transient_poll_does_not_repeat_generic_warning(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(loop.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(loop.threading, "Thread", lambda **kwargs: type("Thread", (), {"start": lambda self: None})())
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.poll_retry_delay = 1
    agent.last_auth_warning = float("-inf")
    agent.fatal = []
    agent.processes = {}
    agent._poll_body = lambda: {}
    attempts = []

    def verify(response, endpoint):
        agent._transient_status(401)
        raise ValueError("transient relay status 401")

    monkeypatch.setattr(agent, "_post", lambda *args: attempts.append(args) or httpx.Response(401))
    monkeypatch.setattr(agent, "_verify_response", verify)

    def wait(delay):
        if len(attempts) == 3:
            agent.stop_event.set()
        return False

    monkeypatch.setattr(agent.stop_event, "wait", wait)
    agent.run_forever()
    warnings = [record.message for record in caplog.records if record.levelno >= 30]
    assert len(attempts) == 3
    assert sum("Relay returned HTTP 401" in message for message in warnings) == 1
    assert not any("Device poll failed" in message for message in warnings)


def test_pair_accepts_correctly_signed_reply(monkeypatch):
    private, public = generate_keypair()
    _, device_public = generate_keypair()
    monkeypatch.setattr(cli, "get_or_create", lambda: (private, device_public))
    monkeypatch.setattr(cli.policy, "digest", lambda: "policy-hash")
    monkeypatch.setattr(config, "load", lambda: {})
    saved = []
    monkeypatch.setattr(config, "save", lambda data: saved.append(data))
    body = canonical_json({"device_id": "device-1", "relay_public_key": b64u(public)})
    ts = int(time.time())
    path = "/api/plugins/hermes-hands/pair"

    def post(url, **kwargs):
        request = httpx.Request("POST", url, headers=kwargs["headers"], content=kwargs["content"])
        return httpx.Response(200, content=body, request=request, headers={
            "X-Hands-Ts": str(ts), "X-Hands-Nonce": "relay-nonce",
            "X-Hands-Signature": sign_request(private, R2D, ts, "relay-nonce", "POST", path, body),
        })

    monkeypatch.setattr(cli.httpx, "post", post)
    assert cli._pair("https://example.test", "test device", "pair-code") == 0
    assert saved == [{"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)}]


def test_loop_rejects_bad_signature(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    response = httpx.Response(200, content=b'{"job_id":"x","type":"exec","script":"echo bad"}', headers={"X-Hands-Ts": str(int(time.time())), "X-Hands-Nonce": "n", "X-Hands-Signature": "bad"})
    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: response))
    try:
        try:
            signed_response = agent._post("/device/poll", {"wait": 25})
            agent._verify_response(signed_response, "/device/poll")
        except PermissionError:
            pass
        else:
            raise AssertionError("bad signature accepted")
    finally:
        agent.client.close()


def test_loop_requires_reply_nonce_to_match_request(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    body = b'{"job_id":"x","type":"exec","script":"echo bad"}'
    ts = int(time.time())

    def handler(request):
        path = "/api/plugins/hermes-hands/device/poll"
        return httpx.Response(200, content=body, request=request, headers={
            "X-Hands-Ts": str(ts), "X-Hands-Nonce": "different",
            "X-Hands-Signature": sign_request(private, R2D, ts, "different", "POST", path, body),
        })

    agent = loop.DeviceLoop(transport=httpx.MockTransport(handler))
    try:
        try:
            agent._verify_response(agent._post("/device/poll", {"wait": 25}), "/device/poll")
        except PermissionError:
            pass
        else:
            raise AssertionError("reply with an unrelated nonce accepted")
    finally:
        agent.client.close()


@pytest.mark.parametrize("status,error", [(401, "unknown_device"), (409, "policy_changed")])
def test_auth_control_replies_require_valid_signature(monkeypatch, status, error):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)))
    request = httpx.Request("POST", "https://example.test/device/poll", headers={"X-Hands-Nonce": "request-nonce"})
    response = httpx.Response(status, json={"error": error}, request=request)
    try:
        with pytest.raises(ValueError, match="transient relay status"):
            agent._verify_response(response, "/device/poll")
    finally:
        agent.client.close()


def test_result_retries_unverified_transient_status_without_ending_job(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.job_deadlines = {"job": time.monotonic() + 10}
    agent.processes = {"job": (type("Proc", (), {"poll": lambda self: None})(), 0.0)}
    replies = iter((httpx.Response(401), httpx.Response(409), httpx.Response(429), httpx.Response(200)))
    calls = []
    monkeypatch.setattr(agent, "_post", lambda *args: calls.append(args) or next(replies))
    monkeypatch.setattr(agent, "_verify_response", lambda response, endpoint: {} if response.status_code == 200 else (_ for _ in ()).throw(ValueError("transient relay status")))
    monkeypatch.setattr(agent.stop_event, "wait", lambda delay: False)
    agent._result("job", 0, chunk="still running")
    assert len(calls) == 4


def test_signed_error_response_with_wrong_signature_is_transient(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)))
    request = httpx.Request("POST", "https://example.test/device/poll", headers={"X-Hands-Nonce": "nonce"})
    body = canonical_json({"error": "unknown_device"})
    response = httpx.Response(401, content=body, request=request, headers={
        "X-Hands-Ts": str(int(time.time())), "X-Hands-Nonce": "nonce", "X-Hands-Signature": "invalid",
    })
    try:
        with pytest.raises(ValueError, match="transient relay status 401"):
            agent._verify_response(response, "/device/poll")
        assert not agent.stop_event.is_set()
    finally:
        agent.client.close()


@pytest.mark.parametrize("capped,expected", [(False, {"returncode": 125}), (True, {"returncode": 1, "error": "Output exceeded the 64 MiB device limit"})])
def test_loop_distinguishes_output_cap_from_exit_125(monkeypatch, capped, expected):
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes = {}
    agent.running = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    agent.process_lock = threading.Lock()
    agent.stop_event = threading.Event()
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)

    class Process:
        returncode = 125

        def poll(self):
            return self.returncode

    def run(*args, on_start, on_exit, on_capped, **kwargs):
        on_start(Process(), 0.0)
        if capped:
            on_capped()
        on_exit(125)
        yield b"output"

    monkeypatch.setattr(loop.executor, "run", run)
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **values: posted.append(values))
    agent._run_job({"job_id": "job", "type": "exec", "script": "exit 125"})
    assert posted[-1] == {"chunk": "output", "done": True, **expected}


def test_signed_unknown_device_stops_agent(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)))
    request = httpx.Request("POST", "https://example.test/device/poll", headers={"X-Hands-Nonce": "request-nonce"})
    body = canonical_json({"error": "unknown_device"})
    nonce = request.headers["X-Hands-Nonce"]
    path = "/api/plugins/hermes-hands/device/poll"
    ts = int(time.time())
    response = httpx.Response(401, content=body, request=request, headers={
        "X-Hands-Ts": str(ts), "X-Hands-Nonce": nonce,
        "X-Hands-Signature": sign_request(private, R2D, ts, nonce, "POST", path, body),
    })
    try:
        with pytest.raises(PermissionError, match="unknown_device"):
            agent._verify_response(response, "/device/poll")
        assert agent.stop_event.is_set()
    finally:
        agent.client.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows background-job revoke containment")
def test_signed_unknown_device_kills_background_child_after_shell_exit(monkeypatch, tmp_path):
    bash = loop.executor.resolve_bash()
    if not bash:
        pytest.skip("Git Bash is unavailable")
    monkeypatch.setattr(loop.executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(loop.executor.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(loop.executor, "_WINDOWS_JOBS", {})
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(config, "load", lambda: {
        "gateway_url": "https://example.test/api/plugins/hermes-hands",
        "device_id": "device-1",
        "relay_public_key": b64u(public),
    })

    def handler(request):
        if request.url.path.endswith("/device/poll"):
            body = canonical_json({"error": "unknown_device"})
            nonce = request.headers["X-Hands-Nonce"]
            path = "/api/plugins/hermes-hands/device/poll"
            ts = int(time.time())
            return httpx.Response(401, content=body, request=request, headers={
                "X-Hands-Ts": str(ts),
                "X-Hands-Nonce": nonce,
                "X-Hands-Signature": sign_request(private, R2D, ts, nonce, "POST", path, body),
            })
        return httpx.Response(204, request=request)

    agent = loop.DeviceLoop(transport=httpx.MockTransport(handler))
    agent.accepted_policy_hash = loop.policy.snapshot()[0]
    heartbeat_finished = threading.Event()
    heartbeat_loop = agent._heartbeat_loop

    def watch_heartbeat():
        try:
            heartbeat_loop()
        finally:
            heartbeat_finished.set()

    agent._heartbeat_loop = watch_heartbeat
    job_id = "revoke-background"
    pid_file = tmp_path / "child.pid"
    python_code = "import os,time; print(os.getpid(), flush=True); time.sleep(60)"
    command = f"nohup python -c {shlex.quote(python_code)} >{shlex.quote(pid_file.as_posix())} 2>/dev/null &"
    agent._run_job({"job_id": job_id, "type": "exec", "script": command})
    serve_errors = []
    serve_thread = None
    stop_times = []
    exit_states = []
    child_pid = None
    try:
        deadline = time.monotonic() + 5
        pid_text = ""
        while not pid_text and time.monotonic() < deadline:
            if pid_file.exists():
                pid_text = pid_file.read_text(encoding="utf-8-sig").strip()
            time.sleep(0.05)
        assert pid_text
        child_pid = int(pid_text)
        assert job_id not in agent.processes
        assert psutil.pid_exists(child_pid)
        job_entries = tuple(loop.executor._WINDOWS_JOBS.items())
        assert job_entries and loop.executor._windows_job_has_active_processes(job_entries[0][1])
        terminate_calls = []
        terminate_jobs = loop.executor._terminate_windows_jobs

        def track_termination():
            terminate_calls.append(tuple(loop.executor._WINDOWS_JOBS))
            terminate_jobs()

        monkeypatch.setattr(loop.executor, "_terminate_windows_jobs", track_termination)
        cancel_all = agent._cancel_all

        def cancel_for_revoke():
            stop_times.append(time.monotonic())
            cancel_all()

        agent._cancel_all = cancel_for_revoke

        def serve():
            try:
                agent.run_forever()
            except PermissionError as exc:
                serve_errors.append(exc)
            finally:
                exit_states.append((time.monotonic(), psutil.pid_exists(child_pid)))

        serve_thread = threading.Thread(target=serve)
        serve_thread.start()
        serve_thread.join(timeout=5)
        assert not serve_thread.is_alive()
        assert heartbeat_finished.wait(2)
        assert serve_errors and str(serve_errors[0]) == "unknown_device"
        assert agent.stop_event.is_set()
        assert terminate_calls and job_entries[0][0] in terminate_calls[0]
        assert not exit_states[0][1], (job_entries, terminate_calls, psutil.Process(child_pid).ppid())
        assert exit_states[0][0] - stop_times[0] < 3
    finally:
        if serve_thread is not None and serve_thread.is_alive():
            agent.stop_event.set()
            serve_thread.join(timeout=5)
        if child_pid is not None and psutil.pid_exists(child_pid):
            child = psutil.Process(child_pid)
            child.kill()
            psutil.wait_procs([child], timeout=2)
        deadline = time.monotonic() + 2
        while loop.executor._WINDOWS_JOBS and time.monotonic() < deadline:
            time.sleep(0.05)
        agent.client.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows App Execution Alias revoke containment")
def test_signed_heartbeat_revoke_kills_python3_alias_child(monkeypatch, tmp_path):
    bash = loop.executor.resolve_bash()
    if not bash:
        pytest.skip("Git Bash is unavailable")
    alias = loop.executor.subprocess.run(
        [bash, "-c", "command -v python3"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5,
    )
    if (
        alias.returncode
        or "/windowsapps/" not in alias.stdout.strip().replace("\\", "/").lower()
    ):
        pytest.skip("Python 3 App Execution Alias is unavailable inside Git Bash")

    import ctypes
    from ctypes import wintypes
    from datetime import datetime, timezone

    monkeypatch.setattr(loop.executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(loop.executor.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(loop.executor, "_WINDOWS_JOBS", {})
    monkeypatch.setattr(
        loop.policy, "snapshot", lambda: ("accepted-hash", loop.policy.DEFAULTS.copy())
    )
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(
        config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands"
    )
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(
        config,
        "load",
        lambda: {
            "gateway_url": "https://example.test/api/plugins/hermes-hands",
            "device_id": "device-1",
            "relay_public_key": b64u(public),
        },
    )

    revoked = threading.Event()
    heartbeat_ready = threading.Event()
    timestamps = {}

    def handler(request):
        if request.url.path.endswith("/device/heartbeat") and revoked.is_set():
            body = canonical_json({"error": "unknown_device"})
            nonce = request.headers["X-Hands-Nonce"]
            path = "/api/plugins/hermes-hands/device/heartbeat"
            ts = int(time.time())
            return httpx.Response(
                401,
                content=body,
                request=request,
                headers={
                    "X-Hands-Ts": str(ts),
                    "X-Hands-Nonce": nonce,
                    "X-Hands-Signature": sign_request(
                        private, R2D, ts, nonce, "POST", path, body
                    ),
                },
            )
        return httpx.Response(204, request=request)

    agent = loop.DeviceLoop(transport=httpx.MockTransport(handler))
    agent.accepted_policy_hash = "accepted-hash"
    output = ""
    child_pids = []
    child_ready = threading.Event()

    def collect_output(job_id, seq, **values):
        nonlocal output
        output += values.get("chunk", "")
        for line in output.splitlines():
            if line.isdecimal():
                child_pids.append(int(line))
                child_ready.set()
                return

    agent._result = collect_output
    original_verify = agent._verify_response

    def trace_verify(response, endpoint):
        if response.status_code == 401 and endpoint == "/device/heartbeat":
            timestamps["first_signed_401"] = time.monotonic()
            timestamps["first_signed_401_utc"] = datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            )
        result = original_verify(response, endpoint)
        if response.status_code == 204 and endpoint == "/device/heartbeat":
            timestamps["heartbeat_success"] = time.monotonic()
            heartbeat_ready.set()
        return result

    agent._verify_response = trace_verify
    original_cancel = agent._cancel_all

    def trace_cancel():
        timestamps["cancel_all"] = time.monotonic()
        timestamps["cancel_all_utc"] = datetime.now(timezone.utc).isoformat(
            timespec="milliseconds"
        )
        original_cancel()

    agent._cancel_all = trace_cancel
    job = threading.Thread(
        target=agent._run_job,
        args=(
            {
                "job_id": "revoke-alias",
                "type": "exec",
                "script": f"python3 -B -c {shlex.quote('import os,time; print(os.getpid(), flush=True); time.sleep(60)')}",
            },
        ),
    )
    heartbeat = threading.Thread(target=agent._heartbeat_loop)
    tracked = set()

    try:
        job.start()
        assert child_ready.wait(5), "App Execution Alias command did not report its PID"
        child_pid = child_pids[0]
        assert psutil.pid_exists(child_pid)
        proc = next(iter(agent.processes.values()))[0]
        job_handle = loop.executor._WINDOWS_JOBS[proc.pid]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.IsProcessInJob.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        ]
        kernel32.IsProcessInJob.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        child_handle = kernel32.OpenProcess(0x1000, False, child_pid)
        assert child_handle, (
            f"Could not open Python child {child_pid} for IsProcessInJob"
        )
        in_job = wintypes.BOOL()
        try:
            assert kernel32.IsProcessInJob(
                child_handle, wintypes.HANDLE(job_handle), ctypes.byref(in_job)
            )
        finally:
            kernel32.CloseHandle(child_handle)
        alias_in_job = bool(in_job.value)

        root = psutil.Process(proc.pid)
        tracked.add((root.pid, root.create_time()))
        tracked.update(
            (descendant.pid, descendant.create_time())
            for descendant in root.children(recursive=True)
        )
        assert any(pid == child_pid for pid, _ in tracked), (
            "Alias Python was not a descendant of the executor process"
        )

        heartbeat.start()
        assert heartbeat_ready.wait(5), (
            "Device heartbeat did not complete before revoke"
        )
        timestamps["revoke"] = time.monotonic()
        timestamps["revoke_utc"] = datetime.now(timezone.utc).isoformat(
            timespec="milliseconds"
        )
        revoked.set()
        deadline = timestamps["revoke"] + 8
        while time.monotonic() < deadline:
            alive = False
            for pid, started in tracked:
                try:
                    current = psutil.Process(pid)
                except psutil.NoSuchProcess:
                    continue
                if abs(current.create_time() - started) <= 0.01:
                    alive = True
                    break
            if not alive:
                timestamps["process_death"] = time.monotonic()
                timestamps["process_death_utc"] = datetime.now(timezone.utc).isoformat(
                    timespec="milliseconds"
                )
                break
            time.sleep(0.02)

        assert "first_signed_401" in timestamps
        assert "cancel_all" in timestamps
        assert "process_death" in timestamps, (
            f"python3 alias child survived revoke; IsProcessInJob={alias_in_job}"
        )
        assert timestamps["first_signed_401"] - timestamps["revoke"] <= 5.5
        assert timestamps["process_death"] - timestamps["cancel_all"] <= 3
        print(
            "revoke timestamps UTC: "
            f"revoke={timestamps['revoke_utc']} "
            f"first_signed_401={timestamps['first_signed_401_utc']} "
            f"_cancel_all={timestamps['cancel_all_utc']} "
            f"process_death={timestamps['process_death_utc']} "
            f"IsProcessInJob={alias_in_job}"
        )
        heartbeat.join(2)
        job.join(5)
        assert not heartbeat.is_alive()
        assert not job.is_alive()
    finally:
        revoked.set()
        agent.stop_event.set()
        if heartbeat.ident is not None:
            heartbeat.join(2)
        for proc, started in tuple(agent.processes.values()):
            try:
                root = psutil.Process(proc.pid)
                if abs(root.create_time() - started) <= 0.01:
                    tracked.add((root.pid, root.create_time()))
                    tracked.update(
                        (descendant.pid, descendant.create_time())
                        for descendant in root.children(recursive=True)
                    )
            except psutil.NoSuchProcess:
                continue
        for pid, started in reversed(tuple(tracked)):
            try:
                process = psutil.Process(pid)
                if abs(process.create_time() - started) <= 0.01:
                    process.kill()
            except psutil.NoSuchProcess:
                continue
        job.join(5)
        agent.client.close()


def test_retry_backoff_caps_at_3_seconds(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.poll_retry_delay = 1
    delays = []
    agent.stop_event = type("Stop", (), {"wait": lambda self, delay: delays.append(delay)})()
    for _ in range(8):
        agent._retry("poll_retry_delay")
    assert delays == [1, 2, 3, 3, 3, 3, 3, 3]


def test_poll_and_heartbeat_backoff_counters_are_independent():
    agent = object.__new__(loop.DeviceLoop)
    agent.poll_retry_delay = 1
    agent.heartbeat_retry_delay = 1
    waits = []
    agent.stop_event = type("Stop", (), {"wait": lambda self, delay: waits.append(delay)})()
    agent._retry("poll_retry_delay")
    agent._retry("poll_retry_delay")
    agent._retry("heartbeat_retry_delay")
    assert waits == [1, 2, 1]


def test_policy_changed_retry_backoff_caps_at_5_seconds(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.poll_retry_delay = 16
    delays = []
    agent.stop_event = type("Stop", (), {"wait": lambda self, delay: delays.append(delay)})()
    agent._retry("poll_retry_delay", cap=5)
    assert delays[0] == 5
    assert agent.poll_retry_delay == 5


def test_heartbeat_retries_within_5_seconds_after_policy_changed(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.heartbeat_retry_delay = 30
    agent.policy_change_logged = False
    agent.last_auth_warning = 0
    attempts, delays = [], []
    monkeypatch.setattr(agent, "_heartbeat_body", lambda: {})
    monkeypatch.setattr(agent, "_post", lambda *args: attempts.append(args) or httpx.Response(200))

    def verify(response, endpoint):
        if len(attempts) == 1:
            raise PermissionError("policy_changed")
        agent.stop_event.set()
        return {}

    monkeypatch.setattr(agent, "_verify_response", verify)
    monkeypatch.setattr(agent.stop_event, "wait", lambda delay: delays.append(delay) or False)
    agent._heartbeat_loop()
    assert len(attempts) == 2
    assert delays[0] == 5


def test_poll_and_heartbeat_share_instance(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.instance = "1234567890abcdef"
    agent.witness = False
    agent.session_state = "normal"
    agent.capabilities = []
    agent._stop_lock = threading.Lock()
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    poll = agent._poll_body()
    heartbeat = agent._heartbeat_body()
    assert poll["instance"] == heartbeat["instance"] == agent.instance
    assert poll["witness"] is heartbeat["witness"] is False
    assert poll["session_state"] == heartbeat["session_state"] == "normal"
    assert poll["capabilities"] == heartbeat["capabilities"] == []


def test_normal_device_advertises_compiled_in_checkup(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    try:
        assert agent.witness is False
        assert agent.session_state == "normal"
        assert agent._poll_body()["capabilities"] == ["checkup-v1"]
        assert agent._heartbeat_body()["capabilities"] == ["checkup-v1"]
    finally:
        agent.client.close()


def test_loop_204_is_no_job_and_non_200_is_not_parsed():
    agent = object.__new__(loop.DeviceLoop)
    assert agent._verify_response(httpx.Response(204), "/device/poll") == {}
    try:
        agent._verify_response(httpx.Response(202, json={"job_id": "x", "type": "exec"}), "/device/poll")
    except ValueError:
        pass
    else:
        raise AssertionError("non-200 reply accepted as a job")


def test_loop_posts_seq_ordered_chunks(monkeypatch):
    posted = []
    agent = object.__new__(loop.DeviceLoop)
    agent.processes = {}
    agent.running = {}
    agent.stop_event = threading.Event()
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    monkeypatch.setattr(loop.executor, "run", lambda *a, **kw: iter((b"one", b"two")))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append((seq, kwargs)))
    agent._run_job({"job_id": "job", "type": "exec", "script": "echo hi"})
    assert [seq for seq, _ in posted] == [0, 1, 2]
    assert posted[-1][1]["done"] is True


def test_exec_refuses_changed_policy_and_posts_current_hash(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.processes, agent.running = {}, {}
    agent.stop_event = threading.Event()
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("new-hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.executor, "run", lambda *a, **kw: pytest.fail("job ran under unaccepted policy"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "old-hash"
    agent._run_job({"job_id": "changed", "type": "exec", "script": "echo hi"})
    assert posted == [{"chunk": "Device policy changed. The owner must run /hands accept-policy <device>.\n", "done": True, "returncode": 126, "policy_hash": "new-hash"}]


def test_exec_runs_when_policy_matches_accepted_hash(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.processes, agent.running = {}, {}
    agent.stop_event = threading.Event()
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("same-hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.executor, "run", lambda *a, **kw: iter(()))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "same-hash"
    agent._run_job({"job_id": "same", "type": "exec", "script": "echo hi"})
    assert posted == [{"chunk": "", "done": True, "returncode": 0}]


def test_loop_incrementally_decodes_split_utf8(monkeypatch):
    posted = []
    agent = object.__new__(loop.DeviceLoop)
    agent.processes, agent.running = {}, {}
    agent.stop_event = threading.Event()
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    monkeypatch.setattr(loop.executor, "run", lambda *a, **kw: iter((b"\xe4\xb8", b"\xad")))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent._run_job({"job_id": "utf8", "type": "exec", "script": "echo hi"})
    assert "".join(item["chunk"] for item in posted) == "\u4e2d"


def test_loop_passes_base64_stdin_to_executor(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes = {}
    agent.running = {}
    agent.stop_event = threading.Event()
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    received = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: received.append(kwargs) or iter(()))
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: None)
    agent._run_job({"job_id": "stdin-b64", "type": "exec", "script": "cat", "stdin_b64": "Y2Fm6Q=="})
    assert received[0]["stdin_b64"] == "Y2Fm6Q=="


def test_loop_drains_all_output_when_result_posts_are_slow(monkeypatch, tmp_path):
    bash = loop.executor.resolve_bash()
    if not bash:
        import pytest

        pytest.skip("bash is unavailable")
    monkeypatch.setattr(loop.executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(loop.executor.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes, agent.running = {}, {}
    agent.cancelled_jobs, agent.job_deadlines = set(), {}
    agent.stop_event = threading.Event()
    output = []

    def slow_result(job_id, seq, **kwargs):
        time.sleep(0.5)
        output.append(kwargs.get("chunk", ""))

    agent._result = slow_result
    agent._run_job({"job_id": "slow-output", "type": "exec", "script": "head -c 200000 /dev/zero | tr '\\000' x", "timeout": 30})
    assert "".join(output).encode() == b"x" * 200_000


def test_loop_finishes_when_post_exit_pipe_is_idle(monkeypatch, tmp_path):
    bash = loop.executor.resolve_bash()
    if not bash:
        pytest.skip("bash is unavailable")
    monkeypatch.setattr(loop.executor, "resolve_bash", lambda: bash)
    monkeypatch.setattr(loop.executor.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(loop.executor, "PIPE_DRAIN_GRACE", 0.1)
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes, agent.running = {}, {}
    agent.cancelled_jobs, agent.job_deadlines = set(), {}
    agent.stop_event = threading.Event()
    posted = []
    agent._result = lambda job_id, seq, **kwargs: posted.append(kwargs)

    agent._run_job({"job_id": "idle-pipe", "type": "exec", "script": "sleep 0.6 & echo early", "timeout": 5})
    time.sleep(0.7)
    assert "".join(item.get("chunk", "") for item in posted) == "early\n"
    assert posted[-1]["done"] is True
    assert posted[-1]["returncode"] == 0


def test_model_workdir_inside_eval_is_checked_for_self_protection(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes = {}
    agent.running = {}
    agent.stop_event = threading.Event()
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    agent.process_lock = threading.Lock()
    posted = []
    ran = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: ran.append(args[0]) or iter(()))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    script = "builtin cd -- '/home/u/project' 2>/dev/null || true\n" + _core_wrapped(
        "builtin cd -- ~/.hermes-hands || exit 126\ncat device.json"
    )

    agent._run_job({"job_id": "model-workdir", "type": "exec", "script": script})

    assert ran == []
    assert posted == [{
        "chunk": f"Policy refused command matching: {loop.policy.DEFAULTS[1]}\n",
        "done": True,
        "returncode": 126,
    }]


def test_cancel_remembered_before_registration_reaches_terminate(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes = {}
    agent.running = {}
    agent.cancelled_jobs = {"job"}
    agent.job_deadlines = {}
    agent.process_lock = threading.Lock()
    agent.stop_event = threading.Event()
    terminated = []
    process = type("Proc", (), {"poll": lambda self: None})()

    def run(*args, on_start, on_exit, **kwargs):
        on_start(process, 1.0)
        on_exit(137)
        return iter(())

    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.executor, "run", run)
    monkeypatch.setattr(loop.executor, "_terminate", lambda proc, started: terminated.append((proc, started)))
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: None)
    agent._run_job({"job_id": "job", "type": "exec", "script": "sleep 10"})
    assert terminated == [(process, 1.0)]


def test_result_delivery_expiry_stops_later_chunks(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes = {}
    agent.running = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    agent.process_lock = threading.Lock()
    agent.stop_event = threading.Event()
    posted = []
    closed = []

    def chunks(*args, on_start, on_exit, **kwargs):
        try:
            yield b"first"
            yield b"second"
        finally:
            closed.append(True)

    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.executor, "run", chunks)
    monkeypatch.setattr(agent, "_post", lambda *args: (_ for _ in ()).throw(httpx.ConnectError("offline")))
    monkeypatch.setattr(agent.stop_event, "wait", lambda delay: False)
    monkeypatch.setattr(loop.time, "monotonic", lambda: 100.0)
    agent._run_job({"job_id": "job", "type": "exec", "script": "echo x", "timeout": 0})
    assert posted == []
    assert closed == [True]


def test_result_reply_cancel_terminates_registered_job(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.last_auth_warning = 0
    process = type("Proc", (), {"poll": lambda self: None})()
    agent.processes = {"job": (process, 1.0)}
    agent.job_deadlines = {}
    terminated = []
    monkeypatch.setattr(loop.executor, "_terminate", lambda proc, started: terminated.append((proc, started)))
    monkeypatch.setattr(agent, "_post", lambda *args: httpx.Response(200))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {"ok": True, "cancel": True})
    try:
        agent._result("job", 0)
    except InterruptedError:
        pass
    else:
        raise AssertionError("cancel reply did not stop result posting")
    assert terminated == [(process, 1.0)]


def test_result_reply_cancel_before_registration_is_remembered(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    monkeypatch.setattr(agent, "_post", lambda *args: httpx.Response(200))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {"cancel": True})
    try:
        agent._result("job", 0)
    except InterruptedError:
        pass
    assert "job" in agent.cancelled_jobs


def test_loop_sends_output_read_after_exit_with_done(monkeypatch):
    posted = []
    agent = object.__new__(loop.DeviceLoop)
    agent.processes = {}
    agent.running = {}
    agent.stop_event = threading.Event()
    exited = []

    class Process:
        def poll(self):
            return 3 if exited else None

    def run(*args, on_start, on_exit, **kwargs):
        on_start(Process(), 0.0)
        yield b"running "
        exited.append(True)
        yield b"after "
        yield b"exit"
        on_exit(3)

    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    monkeypatch.setattr(loop.executor, "run", run)
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append((seq, kwargs)))
    agent._run_job({"job_id": "job", "type": "exec", "script": "echo hi"})
    assert posted == [(0, {"chunk": "running "}), (1, {"chunk": "after exit", "done": True, "returncode": 3})]


def test_loop_flushes_held_output_before_executor_error(monkeypatch):
    posted = []
    agent = object.__new__(loop.DeviceLoop)
    agent.processes = {}
    agent.running = {}
    agent.stop_event = threading.Event()

    class Process:
        def poll(self):
            return 3

    def run(*args, on_start, on_exit, **kwargs):
        on_start(Process(), 0.0)
        yield b"held output"
        raise RuntimeError("executor failed")

    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    monkeypatch.setattr(loop.executor, "run", run)
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append((seq, kwargs)))
    agent._run_job({"job_id": "job", "type": "exec", "script": "echo hi"})
    assert posted == [
        (0, {"chunk": "held output"}),
        (1, {"done": True, "returncode": 1, "error": "executor failed"}),
    ]


def test_loop_allows_core_background_pid_liveness_probe(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    command = 'kill -0 "$(cat /tmp/hermes_bg_proc-1.pid 2>/dev/null)" 2>/dev/null; echo $?'
    script = _core_wrapped(command)
    assert "eval 'kill -0" in script
    assert loop.policy.refusal(command) is None
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter((b"0\n",)))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent._run_job({"job_id": "probe", "type": "exec", "script": script})
    assert posted == [{"chunk": "0\n"}, {"chunk": "", "done": True, "returncode": 0}]


def test_loop_allows_core_background_pid_probe_with_quoted_space_path(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    pid_path = shlex.quote("/tmp/path with space/hermes_bg_proc-1.pid")
    command = f'kill -0 "$(cat {pid_path} 2>/dev/null)" 2>/dev/null; echo $?'
    script = _core_wrapped(command)
    assert loop.policy.refusal(command) is None
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter((b"0\n",)))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent._run_job({"job_id": "probe-space", "type": "exec", "script": script})
    assert posted == [{"chunk": "0\n"}, {"chunk": "", "done": True, "returncode": 0}]


@pytest.mark.parametrize("path", [
    "/tmp/hermes_bg_proc-1.pid",
    "/tmp/path with space/hermes_bg_proc-1.pid",
])
def test_loop_allows_core_background_probe_with_old_policy(monkeypatch, tmp_path, path):
    monkeypatch.setattr(config, "POLICY_PATH", tmp_path / "policy.json")
    config.POLICY_PATH.write_text(
        canonical_json({"deny": [r"\b(?:taskkill|Stop-Process|kill)\b.*(?:hermes-hands|\\1|\b(?:PID|pid)\b)"]}).decode(),
        encoding="utf-8",
    )
    command = f'kill -0 "$(cat {shlex.quote(path)} 2>/dev/null)" 2>/dev/null; echo $?'
    script = _core_wrapped(command)
    assert loop.policy.refusal(command)
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter((b"0\n",)))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent._run_job({"job_id": "old-policy-probe", "type": "exec", "script": script})
    assert posted == [{"chunk": "0\n"}, {"chunk": "", "done": True, "returncode": 0}]


def test_loop_does_not_strip_injected_shell_from_quoted_pid_path(monkeypatch):
    command = "kill -0 \"$(cat " + shlex.quote("/tmp/'; kill -9 $PPID; '/hermes_bg_proc-1.pid") + " 2>/dev/null)\" 2>/dev/null; echo $?"
    script = _core_wrapped(command)
    agent = object.__new__(loop.DeviceLoop)
    agent.processes = {}
    agent.running = {}
    agent.stop_event = threading.Event()
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter(()))
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    agent._run_job({"job_id": "injected-path", "type": "exec", "script": script})
    assert posted == [{"chunk": f"Policy refused command matching: {loop.policy.refusal(script)}\n", "done": True, "returncode": 126}]


def test_loop_refuses_denied_commands_even_when_preceded_by_background_probe(monkeypatch):
    probe = 'kill -0 "$(cat /tmp/hermes_bg_proc-1.pid 2>/dev/null)" 2>/dev/null; echo $?'
    commands = (
        probe + "; kill -9 $PPID",
        probe + f"; taskkill /PID {os.getpid()} /F",
        f'echo "{probe}"; hermes-hands unpair',
        'kill -0 "$(cat ~/.hermes-hands/agent.pid 2>/dev/null)" 2>/dev/null; echo $?; kill -9 $PPID',
        probe + "; shutdown now",
    )
    for command in commands:
        script = _core_wrapped(command)
        agent = object.__new__(loop.DeviceLoop)
        agent.processes = {}
        agent.running = {}
        agent.stop_event = threading.Event()
        posted = []
        monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
        monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter(()))
        monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
        agent.accepted_policy_hash = "hash"
        agent._run_job({"job_id": "denied", "type": "exec", "script": script})
        assert posted == [{"chunk": f"Policy refused command matching: {loop.policy.refusal(script)}\n", "done": True, "returncode": 126}]


def test_loop_checks_hash_and_refusal_from_one_policy_snapshot(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    snapshots = []
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: snapshots.append(True) or ("hash", [r"\bsudo\b"]))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("denied command ran"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "hash"

    agent._run_job({"job_id": "snapshot", "type": "exec", "script": _core_wrapped("sudo id")})

    assert snapshots == [True]
    assert posted == [{"chunk": "Policy refused command matching: \\bsudo\\b\n", "done": True, "returncode": 126}]


def test_loop_ignores_deny_words_in_wrapper_cwd(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter((b"ok\n",)))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "hash"

    script = _core_wrapped("echo ok")
    script = script.replace("/tmp", "/tmp/sudo/shutdown")
    agent._run_job({"job_id": "cwd-words", "type": "exec", "script": script})

    assert posted[0]["chunk"] == "ok\n"


@pytest.mark.parametrize("command", ["cat <<'EOF'\nhello\nEOF", "echo first \\\n  second"])
def test_loop_extracts_plain_eval_without_scanning_wrapper_cwd(monkeypatch, command):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter((b"ok\n",)))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "hash"

    script = _core_wrapped(command).replace("/tmp", "/tmp/sudo/shutdown")
    agent._run_job({"job_id": "plain-eval", "type": "exec", "script": script})

    assert posted[0]["chunk"] == "ok\n"


def test_file_operation_uses_self_protection_patterns_only(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("protected file operation ran"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "hash"

    agent._run_job({"job_id": "file-op", "type": "exec", "script": "cat ~/.hermes-hands/device.json", "file_op": True})

    assert posted[0]["returncode"] == 126


def test_session_bootstrap_does_not_scan_its_workdir_as_a_command(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter((b"ok\n",)))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "hash"
    bootstrap = "builtin cd -- '/home/u/src/sudo-tools' 2>/dev/null || true\nprintf ready\n"

    agent._run_job({"job_id": "bootstrap", "type": "exec", "script": bootstrap})

    assert posted[0]["chunk"] == "ok\n"


def test_workdir_under_device_home_is_self_protected(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("protected workdir ran"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "hash"

    script = "builtin cd -- '/home/u/.hermes-hands' || exit 126\neval 'cat device.json\\n\\n__hermes_rc=$? __hermes_ps=(\"${PIPESTATUS[@]}\"); (exit $__hermes_rc) && :'"
    agent._run_job({"job_id": "protected-workdir", "type": "exec", "script": script})

    assert posted[0]["returncode"] == 126


def test_file_operation_deny_word_is_not_a_self_protection_refusal(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: iter(()))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent.accepted_policy_hash = "hash"

    agent._run_job({"job_id": "file-op-sudo", "type": "exec", "script": "cat docs/sudo.md", "file_op": True})

    assert posted[-1]["done"] is True
    assert posted[-1]["returncode"] == 0


def test_device_loop_stops_when_pairing_changes(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    pairing = {"gateway_url": "https://owner.test/api", "device_id": "owner", "relay_public_key": ""}
    monkeypatch.setattr(config, "load", lambda: pairing.copy())
    monkeypatch.setattr(config, "relay_public_key", lambda: b"owner-key")
    agent = loop.DeviceLoop(transport=httpx.MockTransport(lambda request: pytest.fail("request sent after pairing changed")))
    pairing["gateway_url"] = "https://attacker.test/api"

    with pytest.raises(PermissionError, match="pairing_changed"):
        agent._post("/device/poll", {})

    assert agent.stop_event.is_set()


def test_probe_wrapper_matches_core_output_when_core_is_importable():
    try:
        from tools.environments.base_session_env import _wrap_command_script
    except ImportError:
        return
    pid_path = shlex.quote("/tmp/a b folder/hermes_bg_proc-1.pid")
    command = f'kill -0 "$(cat {pid_path} 2>/dev/null)" 2>/dev/null; echo $?'
    expected = _wrap_command_script(
        command,
        quoted_cwd="/tmp",
        quoted_snap="/tmp/snapshot",
        snap_tmp_template="/tmp/snapshot.tmp.XXXXXXXXXX",
        passthrough_names=(),
        snapshot_ready=False,
        cwd_marker="__CWD__",
        pipe_marker="__PIPE__",
    )
    assert _core_wrapped(command) == expected
    assert "eval 'kill -0" in expected


def test_loop_retries_result_after_network_error(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    attempts = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"

    def post(endpoint, body):
        attempts.append(body)
        if len(attempts) == 1:
            raise httpx.ConnectError("offline")
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", lambda response, endpoint: {})
    monkeypatch.setattr(agent.stop_event, "wait", lambda delay: False)
    agent._result("job", 0, done=True)
    assert len(attempts) == 2


def test_policy_change_cancels_jobs_without_stopping_agent(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.policy_change_logged = False
    agent.last_auth_warning = 0
    private, public = generate_keypair()
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    agent.gateway_url = "https://example.test/api/plugins/hermes-hands"
    agent.relay_public_key = public
    request = httpx.Request("POST", "https://example.test/device/poll", headers={"X-Hands-Nonce": "nonce"})
    body = canonical_json({"error": "policy_changed"})
    ts = int(time.time())
    response = httpx.Response(409, content=body, request=request, headers={
        "X-Hands-Ts": str(ts), "X-Hands-Nonce": "nonce",
        "X-Hands-Signature": sign_request(private, R2D, ts, "nonce", "POST", "/api/plugins/hermes-hands/device/poll", body),
    })

    try:
        agent._verify_response(response, "/device/poll")
    except PermissionError as exc:
        assert str(exc) == "policy_changed"
    else:
        raise AssertionError("policy change response was accepted")

    assert not agent.stop_event.is_set()
    posted = []
    agent.running = {}
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"
    monkeypatch.setattr(loop.executor, "run", lambda *a, **kw: iter(()))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    agent._run_job({"job_id": "later", "type": "exec", "script": "echo hi"})
    assert posted == [{"chunk": "", "done": True, "returncode": 0}]


def test_stopping_during_result_delivery_does_not_escape_job_thread(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.processes = {}
    agent.running = {}
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    agent.accepted_policy_hash = "hash"

    def post(*args, **kwargs):
        agent.stop_event.set()
        raise httpx.ConnectError("device stopped")

    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(loop.executor, "run", lambda *a, **kw: iter((b"output",)))
    errors = []

    def run():
        try:
            agent._run_job({"job_id": "job", "type": "exec", "script": "echo hi"})
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(2)
    assert not thread.is_alive()
    assert errors == []


def test_result_posts_in_flight_chunk_during_stopping(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.stop_event.set()
    agent.session_state = "stopping"
    agent.stop_flush_deadline = time.monotonic() + 5
    agent._stop_lock = threading.Lock()
    agent.process_lock = threading.Lock()
    agent.processes = {}
    agent.job_deadlines = {}
    posted = []
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: posted.append((endpoint, body)) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})

    agent._result("job", 0, chunk="observed output")

    assert posted == [
        (
            "/device/result",
            {
                "job_id": "job",
                "seq": 0,
                "chunk": "observed output",
                "done": False,
                "policy_hash": "hash",
            },
        )
    ]


def test_result_retries_during_stopping_until_shared_flush_deadline(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.stop_event.set()
    agent.session_state = "stopping"
    agent.stop_flush_deadline = 105.0
    agent._stop_lock = threading.Lock()
    agent.process_lock = threading.Lock()
    agent.processes = {}
    agent.job_deadlines = {}
    now = [100.0]
    attempts = []
    monkeypatch.setattr(loop.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(loop.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))

    def post(endpoint, body):
        attempts.append((endpoint, body))
        now[0] += 2.1
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")

    with pytest.raises(InterruptedError, match="flush"):
        agent._result("job", 0, chunk="observed output")

    assert len(attempts) == 2
    assert now[0] >= agent.stop_flush_deadline


def test_stopping_result_request_timeout_uses_remaining_global_budget(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(
        config,
        "load",
        lambda: {
            "gateway_url": "https://example.test/api/plugins/hermes-hands",
            "device_id": "device-1",
            "relay_public_key": b64u(public),
        },
    )
    timeouts = []
    agent = loop.DeviceLoop(
        transport=httpx.MockTransport(
            lambda request: timeouts.append(request.extensions["timeout"])
            or httpx.Response(204, request=request)
        )
    )
    agent.session_state = "stopping"
    monkeypatch.setattr(loop.time, "monotonic", lambda: 10.0)

    try:
        agent.stop_flush_deadline = 11.25
        agent._post("/device/result", {})
        agent.stop_flush_deadline = 12.5
        agent._post("/device/result", {})
        agent.stop_flush_deadline = 11.25
        agent._post("/device/heartbeat", {})
        agent.stop_flush_deadline = 9.0
        with pytest.raises(InterruptedError, match="flush"):
            agent._post("/device/result", {})
    finally:
        agent.client.close()

    assert [max(timeout.values()) for timeout in timeouts] == [1.25, 2.0, 1.25]


def test_final_heartbeat_follows_an_in_flight_active_heartbeat():
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent._stop_lock = threading.Lock()
    agent.heartbeat_lock = threading.Lock()
    agent.session_state = "active"
    agent.witness = True
    agent.capabilities = ["witness-v1", "checkup-v1", "help-v1", "receipt-v1"]
    agent.instance = "witness-instance"
    entered, release = threading.Event(), threading.Event()
    posted = []

    def post(endpoint, body):
        posted.append(body)
        if body["session_state"] == "active":
            entered.set()
            assert release.wait(1)
        return httpx.Response(204)

    agent._post = post
    agent._verify_response = lambda *args: {}
    heartbeat = threading.Thread(target=agent._heartbeat_loop)
    heartbeat.start()

    assert entered.wait(1)
    agent._begin_stopping()
    final = threading.Thread(target=agent._send_final_heartbeat)
    final.start()
    time.sleep(0.02)
    assert len(posted) == 1

    release.set()
    final.join(1)
    heartbeat.join(1)

    assert not final.is_alive()
    assert not heartbeat.is_alive()
    assert [body["session_state"] for body in posted] == ["active", "stopped"]
    assert posted[-1]["witness"] is False


@pytest.mark.parametrize(("relay_available", "expected_delivery"), [(True, "confirmed"), (False, "unconfirmed")])
@pytest.mark.parametrize("stop_reason", ["stopped_by_person", "session_timeout"])
def test_stop_flush_writes_local_receipt_and_sends_stopped_heartbeat(
    monkeypatch, tmp_path, relay_available, expected_delivery, stop_reason
):
    private, public = generate_keypair()
    monkeypatch.setattr(loop.config, "ROOT", tmp_path / ".hermes-hands")
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")

    class Console:
        def __init__(self):
            self.outputs = []

        def write(self, text):
            self.outputs.append(text)

    agent = object.__new__(loop.DeviceLoop)
    agent.private = private
    agent.public = public
    agent.device_id = "device-1"
    agent.instance = "0123456789abcdef"
    agent.capabilities = ["witness-v1", "checkup-v1", "help-v1", "receipt-v1"]
    agent.witness = True
    agent.session_state = "active"
    agent.session_started_at = "2026-11-08T10:00:00Z"
    agent.session_deadline = None
    agent.stop_reason = None
    agent.stop_flush_deadline = None
    agent.stop_event = threading.Event()
    agent._stop_lock = threading.Lock()
    agent.heartbeat_lock = threading.Lock()
    agent.process_lock = threading.Lock()
    agent.processes = {}
    agent.running = {}
    agent.job_start_events = {}
    agent.receipt_events = [
        {
            "timestamp": "2026-11-08T10:01:00Z",
            "label": "Running a command",
            "outcome": "Completed with exit code 0",
            "script": "echo private-command",
            "output": "private-output",
        },
        {
            "timestamp": "2026-11-08T10:02:00Z",
            "label": "Help request",
            "outcome": "Accepted by relay",
            "delivery_status": "pending",
            "request_id": "a" * 32,
        },
    ]
    agent.console = Console()
    monkeypatch.setattr(agent, "_cancel_running_jobs", lambda: None)
    posted = []

    def post(endpoint, body):
        posted.append((endpoint, body))
        receipt_file = next((tmp_path / ".hermes-hands" / "receipts").glob("*.json"))
        saved = json.loads(receipt_file.read_text(encoding="utf-8-sig"))["payload"]
        assert saved["shutdown_delivery"] == "pending"
        if not relay_available:
            raise httpx.ConnectError("offline")
        return httpx.Response(204)

    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})

    agent._begin_stopping(reason=stop_reason)
    agent._stop_and_flush()

    assert len(posted) == 1
    endpoint, body = posted[0]
    assert endpoint == "/device/heartbeat"
    assert body["witness"] is False
    assert body["session_state"] == "stopped"
    assert agent.session_state == "stopped"
    receipt_file = next((tmp_path / ".hermes-hands" / "receipts").glob("*.json"))
    text_file = receipt_file.with_suffix(".txt")
    saved = json.loads(receipt_file.read_text(encoding="utf-8-sig"))["payload"]
    assert saved["end_reason"] == stop_reason
    assert saved["shutdown_delivery"] == expected_delivery
    assert saved["events"][-1]["label"] == "Session stopped"
    assert saved["events"][-1]["delivery_status"] == expected_delivery
    assert saved["events"][1]["delivery_status"] == "pending"
    assert "Running a command: Completed with exit code 0" in text_file.read_text(encoding="utf-8-sig")
    assert "Help request: Accepted by relay (delivery: pending)" in text_file.read_text(encoding="utf-8-sig")
    assert "private-command" not in receipt_file.read_text(encoding="utf-8-sig")
    assert "private-output" not in receipt_file.read_text(encoding="utf-8-sig")
    assert any(str(text_file) in output for output in agent.console.outputs)
    assert any(str(receipt_file) in output for output in agent.console.outputs)


def test_stopping_job_reports_observed_output_and_stopped_result(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes = {}
    agent.running = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    agent.job_start_events = {}
    agent.process_lock = threading.Lock()
    agent.stop_event = threading.Event()
    agent.session_state = "normal"
    posted = []
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.policy, "refusal", lambda script, deny=None: None)
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **values: posted.append((seq, values)))

    class Process:
        def poll(self):
            return None

    def run(*args, on_start, on_exit, **kwargs):
        on_start(Process(), 1.0)
        yield b"before stop"
        agent.session_state = "stopping"
        agent.stop_event.set()
        yield b"during stop"
        on_exit(-9)

    monkeypatch.setattr(loop.executor, "run", run)

    agent._run_job({"job_id": "stopped", "type": "exec", "script": "echo output"})

    assert posted == [
        (0, {"chunk": "before stop"}),
        (1, {"chunk": "during stop"}),
        (2, {"chunk": "", "done": True, "returncode": 130, "error": "stopped_by_person"}),
    ]


def test_job_returned_after_stop_is_refused_without_execution(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.processes = {}
    agent.running = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    agent.job_start_events = {}
    agent.process_lock = threading.Lock()
    agent.stop_event = threading.Event()
    agent.stop_event.set()
    agent.session_state = "stopping"
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **values: posted.append(values))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("raced job executed"))

    agent._run_job({"job_id": "raced", "type": "exec", "script": "echo must not run"})

    assert posted == [{"done": True, "returncode": 130, "error": "stopped_by_person"}]


def test_external_stop_event_preserves_agent_restart_semantics(monkeypatch, tmp_path):
    agent = object.__new__(loop.DeviceLoop)
    monkeypatch.setattr(loop.Path, "home", lambda: tmp_path)
    agent.stop_event = threading.Event()
    agent.fatal = []
    agent.running = {}
    agent.processes = {}
    agent.instance = "1234567890abcdef"
    agent.session_state = "normal"
    agent.witness = False
    agent.capabilities = []
    agent._poll_body = lambda: {}
    agent._post = lambda *args: agent.stop_event.set() or httpx.Response(204)
    agent._verify_response = lambda *args: {}
    cancelled = []
    agent._cancel_running_jobs = lambda: cancelled.append(True)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(
        loop.threading,
        "Thread",
        lambda **kwargs: type("Thread", (), {"start": lambda self: None})(),
    )

    agent.run_forever()

    assert cancelled == [True]
    assert agent.session_state == "normal"


def test_run_forever_terminates_jobs_when_loop_exits(monkeypatch, tmp_path):
    agent = object.__new__(loop.DeviceLoop)
    monkeypatch.setattr(loop.Path, "home", lambda: tmp_path)
    agent.stop_event = threading.Event()
    agent.fatal = []
    agent.running = {}
    agent.processes = {"job": (object(), 1.0)}
    agent.instance = "1234567890abcdef"
    agent.session_state = "normal"
    agent.witness = False
    agent.capabilities = []
    agent._stop_lock = threading.Lock()
    calls = []
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(loop.threading, "Thread", lambda **kwargs: type("Thread", (), {"start": lambda self: None})())
    monkeypatch.setattr(agent, "_cancel_running_jobs", lambda: calls.append("cancel"))
    monkeypatch.setattr(agent, "_post", lambda *args: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        agent.run_forever()
    assert calls == ["cancel"]


def test_second_serve_refuses_before_reaping_live_jobs(monkeypatch, tmp_path):
    monkeypatch.setattr(loop.Path, "home", lambda: tmp_path)
    reaps = []
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: reaps.append(True))
    entered, release = threading.Event(), threading.Event()

    def make_agent():
        agent = object.__new__(loop.DeviceLoop)
        agent.stop_event = threading.Event()
        agent.processes = {}
        agent.running = {}
        agent.fatal = []
        agent.instance = "0123456789abcdef"
        agent.poll_retry_delay = 1
        agent._poll_body = lambda: {}
        agent._heartbeat_loop = lambda: None
        agent._send_final_heartbeat = lambda: False

        def wait_for_release(*args):
            entered.set()
            assert release.wait(2)
            raise KeyboardInterrupt

        agent._post = wait_for_release
        return agent

    first = make_agent()
    second = make_agent()
    errors = []

    def serve_first():
        try:
            first.run_forever()
        except KeyboardInterrupt:
            errors.append("stopped")

    thread = threading.Thread(target=serve_first)
    thread.start()
    try:
        assert entered.wait(2)
        with pytest.raises(RuntimeError, match="already running"):
            second.run_forever()
        assert reaps == [True]
    finally:
        release.set()
        thread.join(2)
    assert errors == ["stopped"]


def test_checkup_job_returns_only_the_compiled_checkup(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.process_lock = threading.Lock()
    agent.processes = {}
    agent.running = {}
    agent.job_start_events = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    agent.receipt_events = []
    agent.witness = True
    agent.console = type("Console", (), {"write": lambda self, text: self.outputs.append(text)})()
    agent.console.outputs = []
    result = {"schema_version": 1, "observed_at": "2026-11-08T00:00:00Z", "platform": "test", "facts": [], "inferences": []}
    posted = []
    monkeypatch.setattr(loop, "_utc_timestamp", lambda: "2026-11-09T00:00:00Z")
    monkeypatch.setattr(loop.checkup, "collect", lambda: result)
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append((job_id, seq, kwargs)))

    agent._run_job({"job_id": "checkup-1", "type": "checkup"})

    assert posted == [
        (
            "checkup-1",
            0,
            {"done": True, "returncode": 0, "error": None, "checkup": result},
        )
    ]
    assert agent.receipt_events[-1]["checkup"] == result
    console_output = "".join(agent.console.outputs)
    assert console_output == (
        "[2026-11-09T00:00:00Z] System checkup: Started\n"
        "[2026-11-08T00:00:00Z] System checkup: Completed\n"
    )
    assert console_output.index("System checkup") < console_output.index("Completed")


@pytest.mark.parametrize(
    "job",
    [
        {"job_id": "unknown-1", "type": "shell"},
        {"job_id": "malformed-1", "type": "checkup", "command": "whoami"},
        {"job_id": "malformed-2", "type": "cancel"},
    ],
)
def test_unknown_or_malformed_jobs_are_refused_and_recorded(monkeypatch, job):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.process_lock = threading.Lock()
    agent.processes = {}
    agent.running = {}
    agent.job_start_events = {}
    agent.cancelled_jobs = set()
    agent.job_deadlines = {}
    agent.receipt_events = []
    agent.witness = True
    agent.console = type("Console", (), {"outputs": [], "write": lambda self, text: self.outputs.append(text)})()
    posted = []
    monkeypatch.setattr(loop, "_utc_timestamp", lambda: "2026-11-09T00:00:00Z")
    monkeypatch.setattr(loop.checkup, "collect", lambda: pytest.fail("malformed checkup ran"))
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("unknown job ran"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append((job_id, seq, kwargs)))

    agent._run_job(job)

    assert posted == [
        (
            job["job_id"],
            0,
            {"done": True, "returncode": 126, "error": "unknown_job_type"},
        )
    ]
    assert agent.receipt_events[0]["outcome"] == "Refused: unknown_job_type"
    assert agent.console.outputs == [
        "[2026-11-09T00:00:00Z] Unknown job type: Refused: unknown_job_type\n"
    ]


class TranscriptConsole:
    def __init__(self):
        self.outputs = []

    def write(self, text):
        self.outputs.append(text)


def _transcript_agent():
    agent = object.__new__(loop.DeviceLoop)
    agent.accepted_policy_hash = "hash"
    agent.allow_screen = True
    agent.cancelled_jobs = set()
    agent.console = TranscriptConsole()
    agent.instance = "transcript-instance"
    agent.job_deadlines = {}
    agent.job_start_events = {}
    agent.processes = {}
    agent.process_lock = threading.Lock()
    agent.receipt_events = []
    agent.running = {}
    agent.session_state = "active"
    agent.stop_event = threading.Event()
    agent.witness = True
    return agent


@pytest.mark.parametrize(
    ("job_id", "script", "file_op", "expected_command"),
    [
        ("exec-transcript", _core_wrapped("ls /mnt/c/Users"), False, "ls /mnt/c/Users"),
        ("read-transcript", "  cat /mnt/c/Users/gudma/notes.txt  ", True, "cat /mnt/c/Users/gudma/notes.txt"),
        ("write-transcript", "  printf '%s' hello > /mnt/c/Users/gudma/notes.txt  ", True, "printf '%s' hello > /mnt/c/Users/gudma/notes.txt"),
        ("patch-transcript", "  python -c 'print(\"patch\")'  ", True, "python -c 'print(\"patch\")'"),
    ],
)
def test_exec_and_file_operation_jobs_print_and_record_command_transcripts(
    monkeypatch, tmp_path, job_id, script, file_op, expected_command
):
    agent = _transcript_agent()
    timestamps = iter(("2026-11-09T00:00:01Z", "2026-11-09T00:00:02Z"))
    monkeypatch.setattr(loop, "_utc_timestamp", lambda: next(timestamps))
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", loop.policy.DEFAULTS.copy()))
    monkeypatch.setattr(loop.policy, "refusal", lambda command, deny=None: None)
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: None)

    class Process:
        def poll(self):
            return 0

    def run(*args, on_start, on_exit, **kwargs):
        assert agent.console.outputs == [
            f"[2026-11-09T00:00:01Z] Running a command: {expected_command}\n"
        ]
        on_start(Process(), 1.0)
        on_exit(0)
        return iter(())

    monkeypatch.setattr(loop.executor, "run", run)

    agent._run_job({"job_id": job_id, "type": "exec", "script": script, "file_op": file_op})

    assert agent.console.outputs == [
        f"[2026-11-09T00:00:01Z] Running a command: {expected_command}\n",
        "[2026-11-09T00:00:02Z] Running a command: Completed with exit code 0\n",
    ]
    assert [event["label"] for event in agent.receipt_events] == [
        "Running a command",
        "Running a command",
    ]
    assert [event["outcome"] for event in agent.receipt_events] == [
        expected_command,
        "Completed with exit code 0",
    ]
    private, public = generate_keypair()
    monkeypatch.setattr(loop.receipt.config, "ROOT", tmp_path / ".hermes-hands")
    paths = loop.receipt.write_receipt(
        {
            "schema_version": 1,
            "device_id": "device-1",
            "instance": "transcript-instance",
            "started_at": "2026-11-09T00:00:00Z",
            "ended_at": "2026-11-09T00:00:02Z",
            "end_reason": "stopped_by_person",
            "shutdown_delivery": "confirmed",
            "events": agent.receipt_events,
        },
        private,
        public,
    )
    saved = loop.receipt.verify_receipt(paths[0])
    assert saved["events"][0]["outcome"] == expected_command
    receipt_text = paths[1].read_text(encoding="utf-8-sig")
    assert f"[2026-11-09T00:00:01Z] Running a command: {expected_command}" in receipt_text
    assert "[2026-11-09T00:00:02Z] Running a command: Completed with exit code 0" in receipt_text


def test_screenshot_job_prints_and_records_request_and_outcome(monkeypatch):
    agent = _transcript_agent()
    agent.console_owner = PromptOwner(["y"])
    timestamps = iter(("2026-11-09T00:00:01Z", "2026-11-09T00:00:02Z"))
    monkeypatch.setattr(loop, "_utc_timestamp", lambda: next(timestamps))
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: b"png")
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: None)

    agent._run_job({"job_id": "screenshot-transcript", "type": "screenshot"})

    assert agent.console.outputs == [
        "[2026-11-09T00:00:01Z] Screenshot request: Started\n",
        "[2026-11-09T00:00:02Z] Screenshot request: Captured\n",
    ]
    assert [(event["label"], event["outcome"]) for event in agent.receipt_events] == [
        ("Screenshot request", "Started"),
        ("Screenshot request", "Captured"),
    ]


def test_cancel_job_prints_and_records_request_and_outcome(monkeypatch):
    agent = _transcript_agent()
    timestamps = iter(("2026-11-09T00:00:01Z", "2026-11-09T00:00:02Z"))
    monkeypatch.setattr(loop, "_utc_timestamp", lambda: next(timestamps))
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: None)

    agent._run_job({"job_id": "cancel-transcript", "type": "cancel", "target_job_id": "job-to-cancel"})

    assert agent.console.outputs == [
        "[2026-11-09T00:00:01Z] Cancellation request: Started\n",
        "[2026-11-09T00:00:02Z] Cancellation request: Cancellation request completed\n",
    ]
    assert [(event["label"], event["outcome"]) for event in agent.receipt_events] == [
        ("Cancellation request", "Started"),
        ("Cancellation request", "Cancellation request completed"),
    ]


def test_result_carries_checkup_object_only_on_final_result(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.stop_event = threading.Event()
    agent.process_lock = threading.Lock()
    checkup_result = {"schema_version": 1, "facts": [], "inferences": []}
    bodies = []
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: bodies.append(body) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})

    agent._result("checkup", 0, done=True, returncode=0, checkup=checkup_result)

    assert bodies == [
        {
            "job_id": "checkup",
            "seq": 0,
            "chunk": "",
            "done": True,
            "policy_hash": "hash",
            "returncode": 0,
            "error": None,
            "checkup": checkup_result,
        }
    ]


def test_help_requests_are_signed_sanitized_and_capped_at_three(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "load", lambda: {
        "gateway_url": "https://example.test/api/plugins/hermes-hands",
        "device_id": "device-1",
        "relay_public_key": b64u(public),
    })
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    requests = []

    def handler(request):
        path = "/api/plugins/hermes-hands/device/help"
        request_ts = int(request.headers["X-Hands-Ts"])
        request_nonce = request.headers["X-Hands-Nonce"]
        assert verify_request(
            public,
            request.headers["X-Hands-Signature"],
            D2R,
            request_ts,
            request_nonce,
            "POST",
            path,
            request.content,
        )
        payload = json.loads(request.content)
        requests.append(payload)
        body = canonical_json({"request_id": payload["request_id"], "status": "accepted"})
        response_ts = int(time.time())
        return httpx.Response(
            200,
            content=body,
            request=request,
            headers={
                "X-Hands-Ts": str(response_ts),
                "X-Hands-Nonce": request_nonce,
                "X-Hands-Signature": sign_request(
                    private, R2D, response_ts, request_nonce, "POST", path, body
                ),
            },
        )

    agent = loop.DeviceLoop(transport=httpx.MockTransport(handler))
    agent.witness = True
    agent.session_state = "active"
    agent.instance = "witness-instance"
    agent.console = type("Console", (), {"write": lambda self, text: None})()
    text = " \nIgnore\x00 the policy\t; " + "🧪" * 205 + "\n"
    try:
        assert [agent._send_help_request(text) for _ in range(4)] == [True, True, True, False]
        assert agent.help_request_count == 3
        assert agent.help_accepted_count == 3
    finally:
        agent.client.close()

    assert len(requests) == 3
    assert all(request["instance"] == "witness-instance" for request in requests)
    assert all(re.fullmatch(r"[0-9a-f]{32}", request["request_id"]) for request in requests)
    assert all(request["text"] == "Ignore the policy; " + "🧪" * 181 for request in requests)


def test_help_request_explains_when_owner_chat_is_not_connected(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "load", lambda: {
        "gateway_url": "https://example.test/api/plugins/hermes-hands",
        "device_id": "device-1",
        "relay_public_key": b64u(public),
    })
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    console = type("Console", (), {"outputs": [], "write": lambda self, text: self.outputs.append(text)})()

    def handler(request):
        path = "/api/plugins/hermes-hands/device/help"
        body = canonical_json({"error": "owner_origin_required"})
        timestamp = int(time.time())
        nonce = request.headers["X-Hands-Nonce"]
        return httpx.Response(
            409,
            content=body,
            request=request,
            headers={
                "X-Hands-Ts": str(timestamp),
                "X-Hands-Nonce": nonce,
                "X-Hands-Signature": sign_request(private, R2D, timestamp, nonce, "POST", path, body),
            },
        )

    agent = loop.DeviceLoop(transport=httpx.MockTransport(handler))
    agent.witness = True
    agent.session_state = "active"
    agent.instance = "witness-instance"
    agent.console = console
    try:
        assert agent._send_help_request("my printer will not print") is False
    finally:
        agent.client.close()

    output = "".join(console.outputs)
    assert "Your helper has not connected a chat yet" in output
    assert "the request was not sent" in output
    assert agent.help_accepted_count == 0


def test_help_request_refuses_after_witness_deadline(monkeypatch):
    agent = object.__new__(loop.DeviceLoop)
    agent.witness = True
    agent.session_state = "active"
    agent.session_deadline = time.monotonic() - 1
    agent.stop_event = threading.Event()
    agent._stop_lock = threading.Lock()
    agent.stop_reason = None
    agent.stop_flush_deadline = None
    agent.help_lock = threading.Lock()
    agent.help_request_count = 0
    monkeypatch.setattr(agent, "_post", lambda *args: pytest.fail("expired help request was sent"))

    assert agent._send_help_request("need help") is False
    assert agent.session_state == "stopping"
    assert agent.stop_reason == "session_timeout"
    assert agent.stop_event.is_set()
    assert agent.help_request_count == 0



