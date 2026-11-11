import json
import signal
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from hermeshands_device import config, loop
from hermeshands_device.protocol import R2D, b64u, canonical_json, generate_keypair, sign_request
from test_loop import PromptOwner, TranscriptConsole
from test_lane_f2_loop import _help_agent


@pytest.fixture
def agent(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "load", lambda: {
        "gateway_url": "https://example.test/api/plugins/hermes-hands",
        "device_id": "device-1", "relay_public_key": b64u(public),
    })
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    instance = loop.DeviceLoop(console=TranscriptConsole())
    instance.witness = True
    instance.session_state = "active"
    instance.session_started_at = "2026-11-11T10:00:00Z"
    instance.accepted_policy_hash = "hash"
    instance.console_owner = PromptOwner(["Y"])
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", []))
    monkeypatch.setattr(loop.policy, "refusal", lambda *args: None)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(instance, "_cancel_running_jobs", lambda: None)
    monkeypatch.setattr(instance, "_heartbeat_loop", lambda: None)
    monkeypatch.setattr(instance, "_request_session_screenshot_consent", lambda: None)
    monkeypatch.setattr(instance, "_help_loop", lambda: None)
    yield instance
    instance.client.close()


def _receipt():
    path = next((config.ROOT / "receipts").glob("*.json"))
    return json.loads(path.read_text(encoding="utf-8-sig"))["payload"]


@pytest.mark.parametrize("when", ["before_first_upload", "retry", "capture_expiry"])
def test_screenshot_upload_rechecks_stop_and_expiry(agent, monkeypatch, when):
    agent.allow_screen = True
    monkeypatch.setattr(loop.screen, "unavailable", lambda: None)
    clock = [100.0]
    monkeypatch.setattr(loop, "_session_clock", lambda: clock[0])
    agent.session_deadline = 100.1
    posted = []
    original = agent._result

    def result(*args, **kwargs):
        if when == "before_first_upload" and kwargs.get("png"):
            agent._begin_stopping()
        return original(*args, **kwargs)

    def capture(**kwargs):
        if when == "capture_expiry":
            clock[0] = 101.0
        return b"png"

    def post(endpoint, body):
        posted.append(dict(body))
        if when == "retry" and len(posted) == 1:
            agent._begin_stopping()
            raise httpx.ReadTimeout("reply lost")
        return httpx.Response(204)

    monkeypatch.setattr(agent, "_result", result)
    monkeypatch.setattr(loop.screen, "capture", capture)
    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    agent._run_job({"job_id": "screen", "type": "screenshot"})
    unsent = posted[1:] if when == "retry" else posted
    assert unsent and all("png_b64" not in body for body in unsent)
    reason = "session_timeout" if when == "capture_expiry" else "stopped_by_person"
    assert unsent[-1]["error"] == reason
    assert unsent[-1]["returncode"] == (124 if when == "capture_expiry" else 130)
    assert agent.receipt_events[-1]["outcome"] == loop._STOPPED_OUTCOMES[reason]


def test_expiry_at_http_upload_boundary_strips_png_and_bounds_timeout(agent, monkeypatch):
    clock = [100.0]
    agent.session_deadline = 100.1
    monkeypatch.setattr(loop, "_session_clock", lambda: clock[0])
    bearer = loop.make_bearer

    def expire_while_signing(*args, **kwargs):
        clock[0] = 101.0
        return bearer(*args, **kwargs)

    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(204, request=request)

    agent.client.close()
    agent.client = httpx.Client(transport=httpx.MockTransport(handler), timeout=35)
    monkeypatch.setattr(loop, "make_bearer", expire_while_signing)
    agent._result("screen", 0, done=True, png=b"png")
    assert "png_b64" not in json.loads(sent[0].content)
    assert json.loads(sent[0].content)["error"] == "session_timeout"
    assert max(sent[0].extensions["timeout"].values()) <= loop._STOP_REQUEST_TIMEOUT


@pytest.mark.parametrize("when", ["heartbeat", "join"])
def test_second_sigint_during_flush_preserves_receipt_and_end_line(agent, monkeypatch, when):
    agent.console_owner = None
    previous = signal.getsignal(signal.SIGINT)

    def post(endpoint, body):
        if endpoint == "/device/poll":
            raise KeyboardInterrupt()
        if when == "heartbeat":
            signal.raise_signal(signal.SIGINT)
        return httpx.Response(204)

    class JoiningJob:
        def join(self, timeout):
            signal.raise_signal(signal.SIGINT)

    if when == "join":
        agent.running["joining"] = JoiningJob()
    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    with pytest.raises(KeyboardInterrupt):
        agent.run_forever()
    assert _receipt()["shutdown_delivery"] == "confirmed"
    assert loop._SESSION_END_LINES["stopped_by_person"] in agent.console.outputs
    assert signal.getsignal(signal.SIGINT) == previous


def test_final_heartbeat_filesystem_error_still_finalizes_receipt(agent, monkeypatch):
    agent._begin_stopping(reason="error")

    def missing_config(*args):
        raise FileNotFoundError("configuration vanished")

    monkeypatch.setattr(agent, "_post", missing_config)
    agent._stop_and_flush()
    assert _receipt()["shutdown_delivery"] == "unconfirmed"
    assert loop._SESSION_END_LINES["error"] in agent.console.outputs


def test_cleanup_failure_restores_signals_and_releases_serve_lock(agent, monkeypatch):
    agent.console_owner = None
    monkeypatch.setattr(signal, "SIGHUP", 2001, raising=False)
    handlers = {number: object() for number in (signal.SIGINT, signal.SIGTERM, 2001)}
    if hasattr(signal, "SIGBREAK"):
        handlers[getattr(signal, "SIGBREAK")] = object()
    saved = handlers.copy()

    def set_signal(number, handler):
        previous = handlers[number]
        handlers[number] = handler
        return previous

    monkeypatch.setattr(signal, "signal", set_signal)
    monkeypatch.setattr(signal, "getsignal", handlers.__getitem__)
    monkeypatch.setattr(agent, "_post", lambda *args: (_ for _ in ()).throw(KeyboardInterrupt()))
    monkeypatch.setattr(agent, "_send_final_heartbeat", lambda: True)

    def closed_output(text):
        raise ValueError("I/O operation on closed file")

    monkeypatch.setattr(agent.console, "write", closed_output)
    try:
        with pytest.raises(ValueError, match="closed file"):
            agent.run_forever()
        assert handlers == saved
        lock_path = config.ROOT / "serve.lock"
        with lock_path.open("a+b") as handle:
            handle.seek(0)
            if loop.os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        for number, handler in saved.items():
            signal.signal(number, handler)


@pytest.mark.parametrize("failure", ["unsigned", "write", "server", "malformed"])
def test_uncertain_help_delivery_is_pending_and_uses_quota(monkeypatch, failure):
    def reply(request):
        if failure == "write":
            raise httpx.WriteError("partial write", request=request)
        if failure == "server":
            return httpx.Response(500, request=request)
        if failure == "malformed":
            return httpx.Response(200, json={"status": "accepted"}, request=request)
        return httpx.Response(200, json={
            "status": "accepted", "request_id": json.loads(request.content)["request_id"],
        }, request=request)

    instance, _ = _help_agent(monkeypatch, reply)
    try:
        assert instance._send_help_request("Please help") is False
        assert instance.receipt_events[-1]["delivery_status"] == "pending"
        assert instance.help_request_count == 1
        assert instance.help_accepted_count == 0
        assert instance.console.outputs == ["Your message may not have reached your helper.\n"]
    finally:
        instance.client.close()


def test_signed_revoke_during_stop_suppresses_final_heartbeat(agent, monkeypatch):
    def revoked(request):
        body = canonical_json({"error": "unknown_device"})
        ts = int(loop.time.time())
        nonce = request.headers["X-Hands-Nonce"]
        return httpx.Response(401, request=request, content=body, headers={
            "X-Hands-Ts": str(ts), "X-Hands-Nonce": nonce,
            "X-Hands-Signature": sign_request(agent.private, R2D, ts, nonce, "POST", request.url.path, body),
        })

    agent.client.close()
    agent.client = httpx.Client(transport=httpx.MockTransport(revoked))
    agent._begin_stopping()
    with pytest.raises(PermissionError, match="unknown_device"):
        agent._result("job", 0, done=True, returncode=130, error="stopped_by_person")
    heartbeats = []
    monkeypatch.setattr(agent, "_send_final_heartbeat", lambda: heartbeats.append(True))
    agent._stop_and_flush()
    assert heartbeats == []
    assert _receipt()["end_reason"] == "revoked"


def test_pairing_change_marks_running_job_stopped_before_cleanup(agent, monkeypatch):
    def run(*args, on_exit, **kwargs):
        monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://changed.test", "device_id": "other"})
        with pytest.raises(PermissionError, match="pairing_changed"):
            agent._post("/device/poll", {})
        on_exit(-9)
        return iter(())

    monkeypatch.setattr(loop.executor, "run", run)
    agent._run_job({"job_id": "running", "type": "exec", "script": "sleep 600"})
    assert agent.stop_reason == "pairing_changed"
    assert agent.receipt_events[-1]["outcome"] == "Stopped because the session ended"


@pytest.mark.parametrize("reason", ["error", "revoked", "pairing_changed"])
def test_abnormal_end_does_not_claim_person_stopped_running_command(agent, monkeypatch, reason):
    posted = []

    def run(*args, on_exit, **kwargs):
        if reason == "revoked":
            response = httpx.Response(401, json={"error": "unknown_device"})
            monkeypatch.setattr(agent, "_error_signature_valid", lambda *args: True)
            with pytest.raises(PermissionError):
                agent._verify_response(response, "/device/poll")
        else:
            agent._begin_stopping(reason=reason)
        on_exit(-9)
        return iter(())

    monkeypatch.setattr(loop.executor, "run", run)
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: posted.append(kwargs))
    agent._run_job({"job_id": "running", "type": "exec", "script": "sleep 600"})
    assert not any(item.get("error") == "stopped_by_person" for item in posted)
    outcome = agent.receipt_events[-1]["outcome"]
    assert "you stopped" not in outcome and "Completed" not in outcome
    assert "session ended" in outcome


def test_stop_while_printing_command_prevents_executor_launch(agent, monkeypatch):
    record = agent._record_job_event
    posted = []

    def record_then_stop(*args, **kwargs):
        record(*args, **kwargs)
        agent._begin_stopping()

    monkeypatch.setattr(agent, "_record_job_event", record_then_stop)
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("command launched after Stop"))
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: posted.append(kwargs))
    agent._run_job({"job_id": "late", "type": "exec", "script": "echo ran"})
    assert posted == [{"done": True, "returncode": 130, "error": "stopped_by_person"}]


def test_command_console_uses_local_time_and_signed_event_keeps_utc(agent, monkeypatch):
    class LocalDateTime(datetime):
        def astimezone(self, tz=None):
            return super().astimezone(timezone(timedelta(hours=1)))

    monkeypatch.setattr(loop.receipt, "datetime", LocalDateTime)
    agent._record_job_event("Running a command", "echo hello", timestamp="2026-11-11T11:08:39Z")
    assert agent.console.outputs == ["[2026-11-11 12:08] Running a command: echo hello\n"]
    assert agent.receipt_events[-1]["timestamp"] == "2026-11-11T11:08:39Z"


def test_saved_policy_warning_is_visible_in_witness_console(agent, monkeypatch):
    agent.console_owner = None
    config.POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.POLICY_PATH.write_text('{"deny": []}', encoding="utf-8")
    monkeypatch.setattr(agent, "_post", lambda *args: (_ for _ in ()).throw(KeyboardInterrupt()))
    monkeypatch.setattr(agent, "_send_final_heartbeat", lambda: True)
    with pytest.raises(KeyboardInterrupt):
        agent.run_forever()
    assert any("policy.json differs" in text and "policy reset" in text for text in agent.console.outputs)
