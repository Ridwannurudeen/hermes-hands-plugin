import json
import sys
import threading
import time

import httpx
import pytest

from hermeshands_device import config, loop
from hermeshands_device.protocol import R2D, b64u, canonical_json, generate_keypair, sign_request
from test_loop import PromptOwner, TranscriptConsole, _screenshot_agent, _signed_poll, _transcript_agent


def _witness_screenshot_agent(owner, monkeypatch):
    agent = _screenshot_agent(owner, monkeypatch)
    agent.session_started_at = "2026-11-11T10:00:00Z"
    agent.console = TranscriptConsole()
    agent.receipt_events = []
    return agent


@pytest.mark.parametrize("reason", ["stopped_by_person", "session_timeout"])
def test_stop_after_the_job_check_still_prevents_a_screenshot(monkeypatch, reason):
    agent = _witness_screenshot_agent(PromptOwner(["Y"]), monkeypatch)
    posted = []
    record = agent._record_job_event

    def record_then_stop(label, outcome, **kwargs):
        record(label, outcome, **kwargs)
        if outcome == "Started":
            agent._begin_stopping(reason=reason)

    monkeypatch.setattr(agent, "_record_job_event", record_then_stop)
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: pytest.fail("screenshot captured after the stop"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._run_job({"job_id": "screen", "type": "screenshot"})

    returncode = 124 if reason == "session_timeout" else 130
    assert posted == [{"done": True, "returncode": returncode, "error": reason}]


def test_stop_during_capture_does_not_send_the_picture(monkeypatch):
    agent = _witness_screenshot_agent(PromptOwner(["Y"]), monkeypatch)
    posted = []

    def capture(**kwargs):
        agent._begin_stopping()
        return b"png"

    monkeypatch.setattr(loop.screen, "capture", capture)
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._run_job({"job_id": "screen", "type": "screenshot"})

    assert posted == [{"done": True, "returncode": 130, "error": "stopped_by_person"}]


@pytest.mark.parametrize("answer", ["S", "s"])
def test_stop_key_at_the_screenshot_prompt_reports_stopped_by_person(monkeypatch, answer):
    agent = _witness_screenshot_agent(PromptOwner([answer]), monkeypatch)
    posted = []
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: pytest.fail("stopped screenshot was captured"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._run_job({"job_id": "screen", "type": "screenshot"})

    assert posted == [{"done": True, "returncode": 130, "error": "stopped_by_person"}]
    assert agent.stop_reason == "stopped_by_person"


@pytest.mark.parametrize("answer", ["S", "s"])
def test_stop_key_at_the_session_screenshot_question_is_not_a_no(monkeypatch, answer):
    agent = _witness_screenshot_agent(PromptOwner([answer]), monkeypatch)
    agent.allow_screen = False

    agent._request_session_screenshot_consent()

    assert agent._is_stopping()
    assert agent.receipt_events == []
    assert agent.console.outputs == []


def test_screenshot_before_the_session_question_is_answered_is_pending(monkeypatch):
    owner = PromptOwner([])
    agent = _witness_screenshot_agent(owner, monkeypatch)
    agent.allow_screen = False
    agent.screen_session_answered = False
    posted = []
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: pytest.fail("unapproved capture"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._run_job({"job_id": "early", "type": "screenshot"})

    assert owner.requests == []
    assert posted == [{"done": True, "returncode": 126, "error": "screenshot_pending"}]


def test_screenshot_after_session_no_is_not_reported_as_a_per_shot_no(monkeypatch):
    owner = PromptOwner(["N"])
    agent = _witness_screenshot_agent(owner, monkeypatch)
    agent.allow_screen = False
    agent.screen_session_answered = False
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._request_session_screenshot_consent()
    agent._run_job({"job_id": "after-no", "type": "screenshot"})

    assert [request[0] for request in owner.requests] == ["witness-instance-screenshot-session"]
    assert posted == [{"done": True, "returncode": 126, "error": "screenshots_disabled"}]


def test_missing_screen_extra_is_reported_before_any_question(monkeypatch):
    owner = PromptOwner([])
    agent = _witness_screenshot_agent(owner, monkeypatch)
    monkeypatch.setattr(loop.screen, "unavailable", lambda: loop.screen.NOT_INSTALLED)
    posted = []
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: pytest.fail("capture without the screen extra"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._request_session_screenshot_consent()
    agent._run_job({"job_id": "no-extra", "type": "screenshot"})

    assert owner.requests == []
    assert agent.allow_screen is False
    assert posted == [{"done": True, "returncode": 126, "error": loop.screen.NOT_INSTALLED}]
    assert "Screenshots are not set up on this computer, so none will be taken this session.\n" in agent.console.outputs


def test_normal_serve_without_screen_flag_sends_a_fixed_code(monkeypatch):
    agent = _screenshot_agent(PromptOwner([]), monkeypatch)
    agent.witness = False
    agent.allow_screen = False
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._run_job({"job_id": "plain", "type": "screenshot"})

    assert posted == [{"done": True, "returncode": 126, "error": loop.screen.NOT_ALLOWED}]


def test_stopped_command_outcome_uses_plain_words(monkeypatch):
    agent = _transcript_agent()
    agent.session_started_at = "2026-11-11T10:00:00Z"
    monkeypatch.setattr(loop.policy, "snapshot", lambda: ("hash", []))
    monkeypatch.setattr(loop.policy, "refusal", lambda *args: None)
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: None)

    def run(*args, on_start, on_exit, **kwargs):
        agent._begin_stopping()
        on_exit(-9)
        return iter(())

    monkeypatch.setattr(loop.executor, "run", run)
    agent._run_job({"job_id": "stopped", "type": "exec", "script": "sleep 30"})

    outcomes = [event["outcome"] for event in agent.receipt_events]
    assert outcomes == ["sleep 30", "Stopped because you stopped the session"]
    assert not any("stopped_by_person" in text for text in agent.console.outputs)


def test_job_refused_by_the_limit_uses_plain_words(monkeypatch):
    agent = _transcript_agent()
    agent.session_started_at = "2026-11-11T10:00:00Z"
    monkeypatch.setattr(agent, "_result", lambda *args, **kwargs: None)
    agent._begin_stopping(reason="session_timeout")
    agent._run_job({"job_id": "late", "type": "exec", "script": "echo late"})
    assert [event["outcome"] for event in agent.receipt_events] == ["Not run because the 30 minute limit was reached"]


def test_two_line_command_is_shown_with_a_visible_line_break():
    assert loop._command_text("echo checking disk space #\nrm -rf ~/Documents/Taxes") == (
        "echo checking disk space # [new line] rm -rf ~/Documents/Taxes"
    )
    assert loop._command_text("rm\t-rf ~/x") == "rm -rf ~/x"


def test_long_command_keeps_its_end_visible():
    text = loop._command_text("echo " + "x" * 5000 + " ; rm -rf ~/Documents")
    assert len(text) <= 2000
    assert text.endswith("; rm -rf ~/Documents")
    assert "characters not shown" in text


def _signed_error(request, status, error):
    private = _signed_error.private
    body = canonical_json({"error": error})
    ts = int(time.time())
    nonce = request.headers["X-Hands-Nonce"]
    return httpx.Response(status, content=body, request=request, headers={
        "X-Hands-Ts": str(ts), "X-Hands-Nonce": nonce,
        "X-Hands-Signature": sign_request(private, R2D, ts, nonce, "POST", request.url.path, body),
    })


@pytest.mark.parametrize(("ending", "end_reason", "end_line"), [
    ("unknown_device", "revoked", "Your helper removed this computer, so the session ended. Nothing else will run.\n"),
    ("pairing_changed", "pairing_changed", "The pairing on this computer changed, so the session ended. Nothing else will run.\n"),
    ("oserror", "error", "The session ended because of an error. Nothing else will run.\n"),
])
def test_session_ended_by_revoke_pairing_or_error_still_writes_its_receipt(monkeypatch, ending, end_reason, end_line):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    pairing = {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)}
    monkeypatch.setattr(config, "load", lambda: pairing.copy())
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    _signed_error.private = private
    heartbeats = []

    def handler(request):
        if request.url.path.endswith("/device/heartbeat"):
            heartbeats.append(json.loads(request.content))
            return httpx.Response(204, request=request)
        if ending == "unknown_device":
            return _signed_error(request, 401, "unknown_device")
        if ending == "pairing_changed":
            pairing["gateway_url"] = "https://other.test/api"
            return httpx.Response(204, request=request)
        raise FileNotFoundError("config vanished")

    agent = loop.DeviceLoop(transport=httpx.MockTransport(handler), console=TranscriptConsole())
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(agent, "_heartbeat_loop", lambda: None)
    monkeypatch.setattr(agent, "_request_session_screenshot_consent", lambda: None)
    agent.witness = True
    agent.session_state = "active"
    try:
        with pytest.raises((PermissionError, RuntimeError, FileNotFoundError)):
            agent.run_forever()
    finally:
        agent.client.close()

    receipts = list((config.ROOT / "receipts").glob("*.json"))
    assert len(receipts) == 1
    saved = json.loads(receipts[0].read_text(encoding="utf-8-sig"))["payload"]
    assert saved["end_reason"] == end_reason
    assert saved["events"][-1]["label"] == "Session stopped"
    assert end_line in agent.console.outputs
    assert agent.session_state == "stopped"
    if ending != "oserror":
        assert heartbeats == []


def test_revoke_seen_by_the_heartbeat_still_writes_the_receipt(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(agent, "_request_session_screenshot_consent", lambda: None)
    agent.console = TranscriptConsole()
    agent.witness = True
    agent.session_state = "active"

    def heartbeat_sees_revoke():
        agent.fatal.append(PermissionError("unknown_device"))
        agent.stop_event.set()

    monkeypatch.setattr(agent, "_heartbeat_loop", heartbeat_sees_revoke)

    def post(endpoint, body):
        assert agent.stop_event.wait(1)
        assert endpoint == "/device/poll", f"{endpoint} sent after the revoke"
        return httpx.Response(204)

    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    try:
        agent.run_forever()
    finally:
        agent.client.close()
    [saved] = [json.loads(path.read_text(encoding="utf-8-sig"))["payload"] for path in (config.ROOT / "receipts").glob("*.json")]
    assert saved["end_reason"] == "revoked"


@pytest.mark.parametrize("policy_file", ["old", "default", None])
def test_serve_warns_when_a_saved_policy_is_not_this_version_default(monkeypatch, caplog, policy_file):
    _, agent = _signed_poll(monkeypatch)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(agent, "_heartbeat_loop", lambda: None)
    monkeypatch.setattr(agent, "_post", lambda *args: agent.stop_event.set() or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    if policy_file is not None:
        config.ROOT.mkdir(parents=True, exist_ok=True)
        deny = loop.policy.DEFAULTS[:-1] if policy_file == "old" else loop.policy.DEFAULTS
        config.POLICY_PATH.write_bytes(canonical_json({"deny": deny}))
    try:
        agent.run_forever()
    finally:
        agent.client.close()
    warned = any("policy.json differs" in record.message for record in caplog.records)
    assert warned is (policy_file == "old")


@pytest.mark.parametrize("installed", [True, False])
def test_serve_with_allow_screen_warns_when_screenshot_support_is_unavailable(monkeypatch, caplog, installed):
    _, agent = _signed_poll(monkeypatch)
    agent.allow_screen = True
    monkeypatch.setattr(loop.screen, "unavailable", lambda: None if installed else loop.screen.NOT_INSTALLED)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(agent, "_heartbeat_loop", lambda: None)
    monkeypatch.setattr(agent, "_post", lambda *args: agent.stop_event.set() or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    try:
        agent.run_forever()
    finally:
        agent.client.close()
    warned = any("screenshot support is not available" in record.message for record in caplog.records)
    assert warned is (not installed)


def test_job_handed_out_as_the_limit_passes_gets_the_timeout_result(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(agent, "_heartbeat_loop", lambda: None)
    monkeypatch.setattr(agent, "_request_session_screenshot_consent", lambda: None)
    monkeypatch.setattr(agent, "_send_final_heartbeat", lambda: True)
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("job ran after the limit"))
    agent.console = TranscriptConsole()
    agent.witness = True
    agent.session_state = "active"
    posted = []

    def post(endpoint, body):
        if endpoint == "/device/poll":
            agent.session_deadline = loop._session_clock() - 1
            return httpx.Response(200, request=httpx.Request("POST", "https://example.test"))
        posted.append(body)
        return httpx.Response(204)

    def verify(response, endpoint):
        if endpoint == "/device/poll":
            return {"job_id": "late", "type": "exec", "script": "echo late"}
        return {}

    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", verify)
    try:
        agent.run_forever()
    finally:
        agent.client.close()

    assert [(body["job_id"], body["returncode"], body["error"]) for body in posted] == [("late", 124, "session_timeout")]


def test_last_second_poll_wait_fits_inside_its_request_timeout(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    agent.witness = True
    agent.session_state = "active"
    agent.session_deadline = loop._session_clock() + 0.4
    try:
        assert agent._poll_body()["wait"] <= agent._session_remaining()
    finally:
        agent.client.close()


def test_last_second_of_the_session_is_not_spent_polling_back_to_back(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    monkeypatch.setattr(agent, "_heartbeat_loop", lambda: None)
    monkeypatch.setattr(agent, "_request_session_screenshot_consent", lambda: None)
    monkeypatch.setattr(agent, "_send_final_heartbeat", lambda: True)
    agent.console = TranscriptConsole()
    agent.witness = True
    agent.session_state = "active"
    agent.session_started_at = "2026-11-11T10:00:00Z"
    agent.session_deadline = loop._session_clock() + 0.6
    polls = []
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: polls.append(body["wait"]) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    try:
        agent.run_forever()
    finally:
        agent.client.close()
    assert agent.stop_reason == "session_timeout"
    assert len(polls) <= 2


def test_stop_during_a_slow_checkup_sends_the_stopped_result_at_once(monkeypatch):
    agent = _transcript_agent()
    agent._stop_lock = threading.Lock()
    release = threading.Event()
    monkeypatch.setattr(loop.checkup, "collect", lambda: release.wait(5) or {"observed_at": "x"})
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    job = threading.Thread(target=agent._run_job, args=({"job_id": "slow", "type": "checkup"},))
    job.start()
    try:
        time.sleep(0.1)
        agent._begin_stopping()
        job.join(1)
        assert not job.is_alive()
        assert posted == [{"done": True, "returncode": 130, "error": "stopped_by_person"}]
    finally:
        release.set()
        job.join(5)


def test_stop_flush_keeps_time_for_the_final_heartbeat_when_a_job_hangs(monkeypatch):
    monkeypatch.setattr(loop, "_STOP_FLUSH_SECONDS", 3)
    agent = _transcript_agent()
    agent._stop_lock = threading.Lock()
    agent.heartbeat_lock = threading.Lock()
    agent.capabilities = []
    hung = threading.Event()
    stuck = threading.Thread(target=hung.wait, args=(10,), daemon=True)
    stuck.start()
    agent.running = {"stuck": stuck}
    heartbeats = []
    monkeypatch.setattr(agent, "_cancel_running_jobs", lambda: None)
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: heartbeats.append(body) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    try:
        agent._begin_stopping()
        agent._stop_and_flush()
    finally:
        hung.set()
    assert [body["session_state"] for body in heartbeats] == ["stopped"]


def test_final_heartbeat_is_sent_while_an_active_heartbeat_is_stalled(monkeypatch):
    monkeypatch.setattr(loop, "_STOP_FLUSH_SECONDS", 3)
    agent = _transcript_agent()
    agent._stop_lock = threading.Lock()
    agent.heartbeat_lock = threading.Lock()
    agent.capabilities = []
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")
    posted = []
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: posted.append(body) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    assert agent.heartbeat_lock.acquire()
    try:
        agent._begin_stopping()
        started = time.monotonic()
        assert agent._send_final_heartbeat() is True
        assert time.monotonic() - started < loop._STOP_FLUSH_SECONDS
    finally:
        agent.heartbeat_lock.release()
    assert [body["session_state"] for body in posted] == ["stopped"]


def test_normal_serve_with_no_stdout_survives_network_errors(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)

    def offline(request):
        raise httpx.ConnectError("offline", request=request)

    agent = loop.DeviceLoop(transport=httpx.MockTransport(offline))
    monkeypatch.setattr(agent, "_heartbeat_loop", lambda: None)
    attempts = []

    def retry(counter="poll_retry_delay", *, cap=3):
        attempts.append(counter)
        if len(attempts) >= 2:
            agent.stop_event.set()

    monkeypatch.setattr(agent, "_retry", retry)
    monkeypatch.setattr(sys, "stdout", None)
    try:
        agent.run_forever()
    finally:
        agent.client.close()
    assert len(attempts) >= 2


def test_heartbeat_thread_with_no_stdout_survives_network_errors(monkeypatch):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    monkeypatch.setattr(config, "relay_public_key", lambda: public)

    def offline(request):
        raise httpx.ConnectError("offline", request=request)

    agent = loop.DeviceLoop(transport=httpx.MockTransport(offline))
    attempts = []

    def retry(counter="poll_retry_delay", *, cap=3):
        attempts.append(counter)
        agent.stop_event.set()

    monkeypatch.setattr(agent, "_retry", retry)
    monkeypatch.setattr(sys, "stdout", None)
    try:
        agent._heartbeat_loop()
    finally:
        agent.client.close()
    assert attempts == ["heartbeat_retry_delay"]


def test_connection_notice_is_only_for_witness_sessions(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    notices = []
    monkeypatch.setattr(agent.console_owner, "notice", notices.append)
    try:
        agent._connection_status(False)
        agent.witness = True
        agent._connection_status(True)
        agent._connection_status(False)
    finally:
        agent.client.close()
    assert notices == ["Lost connection to your helper. Trying again. Type S and press Enter to stop."]


def _help_agent(monkeypatch, reply):
    private, public = generate_keypair()
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "load", lambda: {"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(public)})
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    _signed_error.private = private

    def handler(request):
        if callable(reply):
            return reply(request)
        status, error = reply
        if status != 200:
            return _signed_error(request, status, error)
        body = canonical_json({"request_id": json.loads(request.content)["request_id"], "status": "accepted"})
        ts = int(time.time())
        nonce = request.headers["X-Hands-Nonce"]
        return httpx.Response(200, content=body, request=request, headers={
            "X-Hands-Ts": str(ts), "X-Hands-Nonce": nonce,
            "X-Hands-Signature": sign_request(private, R2D, ts, nonce, "POST", request.url.path, body),
        })

    agent = loop.DeviceLoop(transport=httpx.MockTransport(handler))
    agent.witness = True
    agent.session_state = "active"
    agent.console = TranscriptConsole()
    notices = []
    monkeypatch.setattr(agent.console_owner, "notice", notices.append)
    return agent, notices


def _offline(request):
    raise httpx.ConnectError("offline", request=request)


def _lost_reply(request):
    raise httpx.ReadTimeout("reply lost", request=request)


@pytest.mark.parametrize(("reply", "status", "sentence"), [
    ((200, None), "accepted", "Sent. Your helper should see it in their chat soon.\n"),
    (_lost_reply, "pending", "Your message may not have reached your helper.\n"),
    (_offline, "not_sent", "Your message was not sent. Check the internet and try H again.\n"),
    ((429, "rate_limited"), "not_sent", "Your helper cannot receive more messages this session.\n"),
    ((409, "help_disabled"), "not_sent", "Your helper has not turned on messages, so this was not sent.\n"),
    ((409, "witness_inactive"), "not_sent", "This message was not accepted, so it was not sent.\n"),
    ((409, "unsupported_capability"), "not_sent", "This message was not accepted, so it was not sent.\n"),
])
def test_help_delivery_state_is_recorded_and_said_plainly(monkeypatch, reply, status, sentence):
    agent, notices = _help_agent(monkeypatch, reply)
    try:
        agent._send_help_request("my printer will not print")
    finally:
        agent.client.close()
    assert [event["delivery_status"] for event in agent.receipt_events if event["label"] == "Help request"] == [status]
    assert agent.console.outputs == [sentence]
    if not callable(reply):
        assert notices == []


def test_stop_check_right_before_spawn_keeps_the_command_from_starting(monkeypatch):
    agent = _transcript_agent()
    agent._stop_lock = threading.Lock()
    posted = []

    def snapshot():
        agent._begin_stopping()
        return "hash", []

    monkeypatch.setattr(loop.policy, "snapshot", snapshot)
    monkeypatch.setattr(loop.policy, "refusal", lambda *args: None)
    monkeypatch.setattr(loop.executor, "run", lambda *args, **kwargs: pytest.fail("command spawned after the stop"))
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))

    agent._run_job({"job_id": "late", "type": "exec", "script": "echo ran"})

    assert posted == [{"done": True, "returncode": 130, "error": "stopped_by_person"}]
    assert not any("echo ran" in text for text in agent.console.outputs)


def test_stop_kills_tracked_posix_job_groups(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    calls = []
    monkeypatch.setattr(loop.executor, "_terminate_windows_jobs", lambda deadline=None: calls.append("windows"))
    monkeypatch.setattr(loop.executor, "_terminate_posix_groups", lambda deadline=None: calls.append("posix"), raising=False)
    try:
        agent._stop_from_console()
    finally:
        agent.client.close()
    assert "posix" in calls


@pytest.mark.parametrize(("reason", "sent"), [
    ("stopped_by_person", "stopped_by_person"),
    ("session_timeout", "session_timeout"),
    ("revoked", None),
])
def test_stopping_bodies_carry_the_stop_reason_and_active_bodies_do_not(monkeypatch, reason, sent):
    agent = _transcript_agent()
    agent._stop_lock = threading.Lock()
    agent.capabilities = []
    monkeypatch.setattr(loop.policy, "digest", lambda: "hash")
    assert "stop_reason" not in agent._poll_body()
    assert "stop_reason" not in agent._heartbeat_body()
    agent._begin_stopping(reason=reason)
    for body in (agent._poll_body(), agent._heartbeat_body()):
        assert body.get("stop_reason") == sent
    posted = []
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: posted.append(body) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    assert agent._send_final_heartbeat()
    assert posted[0]["session_state"] == "stopped" and posted[0].get("stop_reason") == sent


def test_console_stop_passes_the_flush_deadline_and_survives_one_failed_kill(monkeypatch):
    _, agent = _signed_poll(monkeypatch)
    first, second = object(), object()
    agent.processes["first"] = (first, 1.0)
    agent.processes["second"] = (second, 2.0)
    terminated, deadlines = [], []

    def terminate(proc, started):
        if proc is first:
            raise OSError("access denied")
        terminated.append(proc)

    monkeypatch.setattr(loop.executor, "_terminate", terminate)
    monkeypatch.setattr(loop.executor, "_terminate_windows_jobs", lambda deadline=None: deadlines.append(deadline))
    try:
        agent._stop_from_console()
    finally:
        agent.client.close()
    assert terminated == [second]
    assert deadlines and set(deadlines) == {agent.stop_flush_deadline}
