from __future__ import annotations

import base64
import codecs
import json
import logging
import os
import platform
import queue
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from . import __version__, checkup, config, executor, policy, receipt, screen
from .console import (
    RECEIPT_SAVED,
    SCREENSHOT_REQUEST_PROMPT,
    SCREENSHOT_SESSION_PROMPT,
    SCREENSHOTS_DISABLED,
    ConsoleInput,
    ConsoleOwner,
    TerminalConsole,
)
from .keys import get_or_create
from .protocol import D2R, R2D, canonical_json, fresh, make_bearer, new_nonce, sign_request, verify_request

logger = logging.getLogger(__name__)

_STOP_FLUSH_SECONDS = 5
_STOP_REQUEST_TIMEOUT = 2
_WITNESS_POLL_SECONDS = 2
_SCREENSHOT_REQUEST_TIMEOUT = 30
_WITNESS_SESSION_SECONDS = 30 * 60
_MAX_HELP_REQUESTS = 3

_BACKGROUND_PID_PROBE = re.compile(
    r"(?ms)^eval 'kill -0 \"\$\(cat "
    r"(('\\'')?[^\n;&|$()<>`']*/hermes_bg_[\w-]+\.pid(?:'\\'')?) 2>/dev/null\)\" "
    r"2>/dev/null; echo \$\?(?:\n\n__hermes_rc=\$\? __hermes_ps=\(\"\$\{PIPESTATUS\[@\]\}\"\); "
    r"\(exit \$__hermes_rc\) && :)?'$"
)
_CORE_EVAL_COMMAND = re.compile(
    r"(?ms)^eval '((?:[^']|'\\'')*)\n\n__hermes_rc=\$\? __hermes_ps=\(\"\$\{PIPESTATUS\[@\]\}\"\); \(exit \$__hermes_rc\) && :'$"
)
_CORE_PLAIN_EVAL_COMMAND = re.compile(r"(?m)^eval '((?:[^']|'\\'')*)'$", re.DOTALL)
_CORE_CWD = re.compile(r"(?m)^builtin cd -- (.+?)(?: 2>/dev/null \|\| true| \|\| exit 126)$")


def _sanitize_help_text(text: str) -> str:
    return "".join(character for character in text.strip() if character.isprintable()).strip()[:200]


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _command_text(script: str) -> str:
    wrapped_command = _CORE_EVAL_COMMAND.search(script)
    if not wrapped_command:
        wrapped_command = _CORE_PLAIN_EVAL_COMMAND.search(script)
    if wrapped_command:
        script = wrapped_command.group(1).replace("'\\''", "'")
    else:
        script = _CORE_CWD.sub("", script, count=1)
    return script.strip()


class DeviceLoop:
    def __init__(self, *, allow_screen: bool = False, transport: httpx.BaseTransport | None = None, console: ConsoleInput | None = None):
        self.allow_screen = allow_screen
        self.console = console if console is not None else TerminalConsole()
        self.private, self.public = get_or_create()
        pairing = config.load()
        self.gateway_url = pairing.get("gateway_url", "").rstrip("/")
        self.device_id = pairing.get("device_id", "")
        self.relay_public_key = config.relay_public_key()
        self.running: dict[str, threading.Thread] = {}
        self.job_start_events: dict[str, threading.Event] = {}
        self.processes: dict[str, tuple[object, float]] = {}
        self.cancelled_jobs: set[str] = set()
        self.process_lock = threading.Lock()
        self.job_deadlines: dict[str, float] = {}
        self.stop_event = threading.Event()
        self.session_state = "normal"
        self.witness = False
        self.capabilities: list[str] = ["checkup-v1"]
        self.session_started_at: str | None = None
        self.session_deadline: float | None = None
        self.stop_reason: str | None = None
        self.stop_flush_deadline: float | None = None
        self._stop_lock = threading.Lock()
        self.heartbeat_lock = threading.Lock()
        self.receipt_lock = threading.Lock()
        self.help_requests: queue.Queue[str] = queue.Queue()
        self.help_lock = threading.Lock()
        self.help_request_count = 0
        self.help_accepted_count = 0
        self.receipt_events: list[dict] = []
        self.console_owner = ConsoleOwner(self.console, on_stop=self._stop_from_console, on_help=self.help_requests.put)
        self.fatal: list[Exception] = []
        self.policy_change_logged = False
        self.instance = secrets.token_hex(8)
        self.poll_retry_delay = 1
        self.heartbeat_retry_delay = 1
        self.last_auth_warning = float("-inf")
        self.accepted_policy_hash = None
        self.client = httpx.Client(transport=transport, timeout=35, trust_env=False)

    def _post(self, endpoint: str, body_obj: dict) -> httpx.Response:
        pairing = config.load()
        if (pairing.get("gateway_url", "").rstrip("/"), pairing.get("device_id", ""), config.relay_public_key()) != (self.gateway_url, self.device_id, self.relay_public_key):
            self.stop_event.set()
            raise PermissionError("pairing_changed")
        body = canonical_json(body_obj)
        path = urlparse(self.gateway_url).path.rstrip("/") + endpoint
        ts, nonce = int(time.time()), new_nonce()
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + make_bearer(self.device_id, self.private, ts=ts, nonce=nonce),
            "X-Hands-Ts": str(ts), "X-Hands-Nonce": nonce,
            "X-Hands-Signature": sign_request(self.private, D2R, ts, nonce, "POST", path, body),
        }
        request_options = {}
        remaining = self._stop_flush_remaining()
        if remaining is not None:
            if not remaining:
                raise InterruptedError("stop result flush deadline expired")
            request_options["timeout"] = min(remaining, _STOP_REQUEST_TIMEOUT)
        elif endpoint == "/device/poll":
            session_remaining = self._session_remaining()
            if session_remaining is not None:
                if not session_remaining:
                    self._expire_session_if_due()
                    raise InterruptedError("witness session expired")
                request_options["timeout"] = session_remaining
        elif endpoint == "/device/help":
            request_options["timeout"] = _STOP_REQUEST_TIMEOUT
        return self.client.post(self.gateway_url + endpoint, content=body, headers=headers, **request_options)

    def _verify_response(self, response: httpx.Response, endpoint: str) -> dict:
        if response.status_code in (401, 409):
            try:
                payload = response.json()
            except (ValueError, json.JSONDecodeError):
                payload = {}
            expected = "unknown_device" if response.status_code == 401 else "policy_changed"
            error_signature_valid = self._error_signature_valid(response, endpoint)
            if payload.get("error") == expected and error_signature_valid:
                if expected == "unknown_device":
                    self._cancel_all()
                    self.fatal.append(PermissionError("unknown_device"))
                    raise PermissionError("unknown_device")
                self._cancel_running_jobs()
                if not self.policy_change_logged:
                    logger.warning("Relay policy changed; cancelling running jobs and backing off")
                    self.policy_change_logged = True
                raise PermissionError("policy_changed")
            if (
                response.status_code == 409
                and endpoint == "/device/help"
                and payload.get("error") == "owner_origin_required"
                and error_signature_valid
            ):
                raise PermissionError("owner_origin_required")
            self._transient_status(response.status_code)
            raise ValueError(f"transient relay status {response.status_code}")
        if response.status_code == 429:
            self._transient_status(response.status_code)
            raise ValueError("transient relay status 429")
        if response.status_code == 204:
            return {}
        if response.status_code != 200:
            raise ValueError(f"unexpected relay status {response.status_code}")
        if not self._response_signature_valid(response, endpoint):
            logger.warning("Dropping invalid relay reply for %s", endpoint)
            raise PermissionError("invalid relay response")
        payload = response.json()
        if endpoint in ("/device/heartbeat", "/device/result") or (endpoint == "/device/poll" and payload):
            request = json.loads(response.request.content)
            self.accepted_policy_hash = request["policy_hash"]
        return payload

    def _response_signature_valid(self, response: httpx.Response, endpoint: str) -> bool:
        try:
            ts = int(response.headers["X-Hands-Ts"])
            nonce = response.headers["X-Hands-Nonce"]
            request_nonce = response.request.headers["X-Hands-Nonce"]
            signature = response.headers["X-Hands-Signature"]
            path = urlparse(self.gateway_url).path.rstrip("/") + endpoint
            return nonce == request_nonce and fresh(ts, int(time.time())) and verify_request(
                self.relay_public_key, signature, R2D, ts, nonce, "POST", path, response.content
            )
        except (KeyError, ValueError, httpx.RequestNotRead):
            return False

    def _error_signature_valid(self, response: httpx.Response, endpoint: str) -> bool:
        return self._response_signature_valid(response, endpoint)

    def _transient_status(self, status: int) -> None:
        now = time.monotonic()
        if now - self.last_auth_warning >= 60:
            logger.warning(
                "Relay returned HTTP %s; retrying. Check for clock skew over 300 seconds, a dashboard started without the relay seed, or a device revoked before this version.",
                status,
            )
            self.last_auth_warning = now

    def _retry(self, counter: str = "poll_retry_delay", *, cap: int = 3) -> None:
        if not hasattr(self, counter):
            setattr(self, counter, 1)
        delay = min(cap, getattr(self, counter))
        setattr(self, counter, min(cap, delay * 2))
        session_remaining = self._session_remaining()
        if session_remaining is not None:
            delay = min(delay, session_remaining)
        self.stop_event.wait(delay)

    def _poll_body(self) -> dict:
        wait = 25
        if self.witness and self.session_state == "active":
            wait = min(wait, _WITNESS_POLL_SECONDS)
        remaining = self._session_remaining()
        if remaining is not None:
            wait = min(wait, max(1, int(remaining)))
        return {
            "wait": wait,
            "policy_hash": policy.digest(),
            "instance": self.instance,
            **self._session_status(),
        }

    def _heartbeat_body(self) -> dict:
        return {
            "policy_hash": policy.digest(),
            "os": platform.platform(),
            "home": str(Path.home()),
            "agent_version": __version__,
            "instance": self.instance,
            **self._session_status(),
        }

    def _session_status(self) -> dict:
        with self._stop_lock:
            return {
                "witness": self.witness,
                "session_state": self.session_state,
                "capabilities": self.capabilities.copy(),
            }

    def _record_receipt_event(
        self,
        label: str,
        outcome: str,
        *,
        timestamp: str | None = None,
        checkup_result: dict | None = None,
        delivery_status: str | None = None,
        request_id: str | None = None,
    ) -> None:
        if not getattr(self, "witness", False) and getattr(self, "session_started_at", None) is None:
            return
        if not hasattr(self, "receipt_events"):
            self.receipt_events = []
        if not hasattr(self, "receipt_lock"):
            self.receipt_lock = threading.Lock()
        event = {
            "timestamp": timestamp or _utc_timestamp(),
            "label": label,
            "outcome": outcome,
        }
        if checkup_result is not None:
            event["checkup"] = checkup_result
        if delivery_status is not None:
            event["delivery_status"] = delivery_status
        if request_id is not None:
            event["request_id"] = request_id
        with self.receipt_lock:
            self.receipt_events.append(event)

    def _record_job_event(
        self,
        label: str,
        outcome: str,
        *,
        timestamp: str | None = None,
        checkup_result: dict | None = None,
    ) -> None:
        timestamp = _utc_timestamp() if timestamp is None else timestamp
        if getattr(self, "witness", False) or getattr(self, "session_started_at", None) is not None:
            console = getattr(self, "console", None)
            if console is not None:
                console.write(f"[{timestamp}] {label}: {outcome}\n")
        self._record_receipt_event(
            label,
            outcome,
            timestamp=timestamp,
            checkup_result=checkup_result,
        )

    def _request_session_screenshot_consent(self) -> None:
        answer = self.console_owner.request(
            f"{self.instance}-screenshot-session",
            SCREENSHOT_SESSION_PROMPT,
        )
        if self.stop_event.is_set():
            return
        self.allow_screen = answer is not None and answer.strip().casefold() == "y"
        self._record_receipt_event(
            "Screenshot session permission",
            "Enabled" if self.allow_screen else "Disabled",
        )
        if not self.allow_screen:
            self.console.write(SCREENSHOTS_DISABLED)

    def _is_stopping(self) -> bool:
        return getattr(self, "session_state", "normal") == "stopping"

    def _session_remaining(self) -> float | None:
        deadline = getattr(self, "session_deadline", None)
        if (
            deadline is None
            or not getattr(self, "witness", False)
            or getattr(self, "session_state", "normal") != "active"
        ):
            return None
        return max(0.0, deadline - time.monotonic())

    def _expire_session_if_due(self) -> bool:
        remaining = self._session_remaining()
        if remaining is None or remaining > 0:
            return False
        self._begin_stopping(reason="session_timeout")
        return True

    def _stopped_result(self) -> tuple[int, str]:
        if getattr(self, "stop_reason", None) == "session_timeout":
            return 124, "session_timeout"
        return 130, "stopped_by_person"

    def _stop_flush_remaining(self) -> float | None:
        with self._stop_lock:
            if not self._is_stopping():
                return None
            deadline = getattr(self, "stop_flush_deadline", None)
            if deadline is None:
                return 0.0
            return max(0.0, deadline - time.monotonic())

    def _begin_stopping(self, reason: str = "stopped_by_person") -> float:
        if not hasattr(self, "_stop_lock"):
            self._stop_lock = threading.Lock()
        with self._stop_lock:
            if getattr(self, "session_state", "normal") == "stopped":
                return getattr(self, "stop_flush_deadline", None) or time.monotonic()
            if not self._is_stopping():
                self.session_state = "stopping"
                self.stop_reason = reason
                self.stop_flush_deadline = time.monotonic() + _STOP_FLUSH_SECONDS
                self.witness = False
            elif getattr(self, "stop_flush_deadline", None) is None:
                self.stop_flush_deadline = time.monotonic() + _STOP_FLUSH_SECONDS
            self.stop_event.set()
            return self.stop_flush_deadline

    def _cancel_all(self) -> None:
        """On revoke, stop foreground and detached Windows jobs before serve exits."""
        self.stop_event.set()
        self._cancel_running_jobs()

    def _stop_from_console(self) -> None:
        self._begin_stopping()
        self._cancel_running_jobs()

    def _cancel_running_jobs(self) -> None:
        if not hasattr(self, "process_lock"):
            self.process_lock = threading.Lock()
        if not hasattr(self, "job_start_events"):
            self.job_start_events = {}
        with self.process_lock:
            processes = list(self.processes.values())
        for proc, started in processes:
            executor._terminate(proc, started)
        executor._terminate_windows_jobs()
        if self.stop_event.is_set():
            with self.process_lock:
                starting = list(self.job_start_events.values())
            for started in starting:
                remaining = self._stop_flush_remaining()
                if remaining is None:
                    started.wait()
                else:
                    started.wait(timeout=remaining)
            executor._terminate_windows_jobs()

    def _send_final_heartbeat(self) -> bool:
        remaining = self._stop_flush_remaining()
        if remaining is None or remaining <= 0:
            return False
        if not hasattr(self, "heartbeat_lock"):
            self.heartbeat_lock = threading.Lock()
        if not self.heartbeat_lock.acquire(timeout=remaining):
            logger.warning("Final device heartbeat was not confirmed before the stop flush deadline")
            return False
        try:
            if not self._stop_flush_remaining():
                return False
            body = self._heartbeat_body()
            body["witness"] = False
            body["session_state"] = "stopped"
            response = self._post("/device/heartbeat", body)
            if response.status_code >= 500:
                response.raise_for_status()
            self._verify_response(response, "/device/heartbeat")
            return response.status_code in (200, 204)
        except (httpx.HTTPError, InterruptedError, PermissionError, ValueError, KeyError) as exc:
            logger.warning("Final device heartbeat was not confirmed (%s)", type(exc).__name__)
            return False
        finally:
            self.heartbeat_lock.release()

    def _stop_and_flush(self) -> None:
        deadline = self._begin_stopping()
        if getattr(self, "session_state", "normal") == "stopped":
            return
        payload = None
        paths = None
        confirmed = False
        try:
            try:
                self._cancel_running_jobs()
                if not hasattr(self, "process_lock"):
                    self.process_lock = threading.Lock()
                with self.process_lock:
                    jobs = list(getattr(self, "running", {}).values())
                for thread in jobs:
                    if thread is not threading.current_thread():
                        thread.join(max(0.0, deadline - time.monotonic()))
                started_at = getattr(self, "session_started_at", None)
                if started_at is not None:
                    ended_at = _utc_timestamp()
                    end_reason = getattr(self, "stop_reason", None) or "stopped_by_person"
                    self._record_receipt_event(
                        "Session stopped",
                        f"Ended: {end_reason}",
                        timestamp=ended_at,
                        delivery_status="pending",
                    )
                    if not hasattr(self, "receipt_lock"):
                        self.receipt_lock = threading.Lock()
                    with self.receipt_lock:
                        events = sorted(
                            (dict(event) for event in self.receipt_events),
                            key=lambda event: event["timestamp"],
                        )
                    payload = {
                        "schema_version": 1,
                        "device_id": self.device_id,
                        "instance": self.instance,
                        "started_at": started_at,
                        "ended_at": ended_at,
                        "end_reason": end_reason,
                        "shutdown_delivery": "pending",
                        "events": events,
                    }
                    try:
                        paths = receipt.write_receipt(payload, self.private, self.public)
                    except OSError as exc:
                        logger.warning("Could not save local session receipt (%s)", type(exc).__name__)
            finally:
                confirmed = self._send_final_heartbeat()
            if payload is not None:
                delivery_status = "confirmed" if confirmed else "unconfirmed"
                payload["shutdown_delivery"] = delivery_status
                for event in payload["events"]:
                    if event["label"] == "Session stopped" and event["timestamp"] == payload["ended_at"]:
                        event["delivery_status"] = delivery_status
                        break
                if paths is not None:
                    try:
                        receipt.update_receipt(paths, payload, self.private, self.public)
                    except OSError as exc:
                        logger.warning("Could not update local session receipt (%s)", type(exc).__name__)
                    self.console.write(RECEIPT_SAVED.format(text_path=paths[1], json_path=paths[0]))
        finally:
            with self._stop_lock:
                self.session_state = "stopped"

    def _result(
        self,
        job_id: str,
        seq: int,
        *,
        chunk: str = "",
        done: bool = False,
        returncode: int = 0,
        error: str | None = None,
        png: bytes | None = None,
        policy_hash: str | None = None,
        checkup: dict | None = None,
    ) -> None:
        if not hasattr(self, "process_lock"):
            self.process_lock = threading.Lock()
        result = {"job_id": job_id, "seq": seq, "chunk": chunk, "done": done, "policy_hash": policy.digest() if policy_hash is None else policy_hash}
        if done:
            result["returncode"] = returncode
            result["error"] = error
        if png is not None:
            result["png_b64"] = base64.b64encode(png).decode("ascii")
        if checkup is not None:
            if not done:
                raise ValueError("checkup data is only valid on a final result")
            result["checkup"] = checkup
        while not self.stop_event.is_set() or self._is_stopping():
            if self._is_stopping() and not self._stop_flush_remaining():
                break
            try:
                response = self._post("/device/result", result)
                if response.status_code >= 500:
                    response.raise_for_status()
                payload = self._verify_response(response, "/device/result")
                if payload.get("cancel"):
                    with self.process_lock:
                        target = self.processes.get(job_id)
                        if target is None:
                            self.cancelled_jobs.add(job_id)
                            if len(self.cancelled_jobs) > 1024:
                                self.cancelled_jobs.pop()
                    if target is not None and target[0].poll() is None:
                        executor._terminate(target[0], target[1])
                    raise InterruptedError("relay cancelled the job")
                return
            except (httpx.HTTPError, ValueError):
                if self._is_stopping():
                    remaining = self._stop_flush_remaining()
                    if not remaining:
                        break
                    time.sleep(min(1.0, remaining))
                else:
                    deadline = getattr(self, "job_deadlines", {}).get(job_id)
                    if deadline is not None and time.monotonic() >= deadline:
                        logger.warning("Stopping job %s after result delivery expired at sequence %s", job_id, seq)
                        raise InterruptedError("result delivery expired")
                    self.stop_event.wait(1)
        logger.debug("Stopping result delivery for %s because the device is stopping", job_id)
        if self._is_stopping():
            raise InterruptedError("stop result flush deadline expired")
        raise InterruptedError("device is stopping")

    def _send_help_request(self, text: str) -> bool:
        clean_text = _sanitize_help_text(text)
        if not clean_text or self._expire_session_if_due() or not self.witness or self.session_state != "active":
            return False
        with self.help_lock:
            if self.help_request_count >= _MAX_HELP_REQUESTS:
                self.console.write("The witness session has reached its three-request help limit.\n")
                return False
            self.help_request_count += 1
            request_id = secrets.token_hex(16)
            request = {
                "request_id": request_id,
                "instance": self.instance,
                "text": clean_text,
            }
            try:
                response = self._post("/device/help", request)
                if response.status_code >= 500:
                    response.raise_for_status()
                payload = self._verify_response(response, "/device/help")
            except PermissionError as exc:
                if str(exc) == "owner_origin_required":
                    self.console.write("Your helper has not connected a chat yet, so the request was not sent.\n")
                else:
                    logger.warning("Help request was not accepted by the relay: %s", type(exc).__name__)
                return False
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                logger.warning("Help request was not accepted by the relay: %s", type(exc).__name__)
                return False
            if (
                response.status_code != 200
                or not isinstance(payload, dict)
                or payload.get("request_id") != request_id
                or payload.get("status") != "accepted"
            ):
                self.console.write("The relay did not accept the help request.\n")
                return False
            self.help_accepted_count += 1
            self._record_receipt_event(
                "Help request",
                "Accepted by relay",
                delivery_status="pending",
                request_id=request_id,
            )
            self.console.write("The relay accepted the help request; owner delivery is pending.\n")
            return True

    def _help_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                text = self.help_requests.get(timeout=0.1)
            except queue.Empty:
                continue
            self._send_help_request(text)

    def _refuse_unknown_job(self, job_id: str, seq: int) -> None:
        self._record_job_event("Unknown job type", "Refused: unknown_job_type")
        self._result(job_id, seq, done=True, returncode=126, error="unknown_job_type")

    def _run_job(self, job: dict, start_event: threading.Event | None = None) -> None:
        job_id, seq = job["job_id"], 0
        job_type = job.get("type")
        receipt_label = {
            "exec": "Command request",
            "checkup": "System checkup",
            "screenshot": "Screenshot request",
            "cancel": "Cancellation request",
        }.get(job_type, "Unknown job type")
        receipt_outcome = None
        receipt_checkup = None
        receipt_timestamp = None
        if not hasattr(self, "cancelled_jobs"):
            self.cancelled_jobs = set()
        if not hasattr(self, "process_lock"):
            self.process_lock = threading.Lock()
        if not hasattr(self, "job_deadlines"):
            self.job_deadlines = {}
        if not hasattr(self, "job_start_events"):
            self.job_start_events = {}
        if start_event is None:
            start_event = threading.Event()
            with self.process_lock:
                self.job_start_events[job_id] = start_event
        if not hasattr(self, "instance"):
            self.instance = secrets.token_hex(8)
        tail = b""
        try:
            self._expire_session_if_due()
            if self._is_stopping():
                start_event.set()
                returncode, error = self._stopped_result()
                receipt_outcome = f"Refused: {error}"
                self._result(
                    job_id,
                    seq,
                    done=True,
                    returncode=returncode,
                    error=error,
                )
                return
            if self.stop_event.is_set():
                start_event.set()
                receipt_label = None
                return
            malformed = not isinstance(job_type, str) or job_type not in {
                "exec",
                "checkup",
                "screenshot",
                "cancel",
            }
            malformed = malformed or (job_type == "exec" and not isinstance(job.get("script"), str))
            malformed = malformed or (job_type == "checkup" and set(job) != {"job_id", "type"})
            malformed = malformed or (job_type == "screenshot" and set(job) != {"job_id", "type"})
            malformed = malformed or (job_type == "cancel" and not isinstance(job.get("target_job_id"), str))
            if malformed:
                start_event.set()
                receipt_label = None
                self._refuse_unknown_job(job_id, seq)
                return
            if job_type != "exec":
                start_event.set()
            if job_type == "exec":
                current_policy_hash, policy_patterns = policy.snapshot()
                if current_policy_hash != getattr(self, "accepted_policy_hash", None):
                    start_event.set()
                    receipt_outcome = "Refused: policy acceptance changed"
                    self._result(
                        job_id,
                        seq,
                        chunk="Device policy changed. The owner must run /hands accept-policy <device>.\n",
                        done=True,
                        returncode=126,
                        policy_hash=current_policy_hash,
                    )
                    return
                script = job["script"]
                policy_script = _BACKGROUND_PID_PROBE.sub("", script)
                wrapped_command = _CORE_EVAL_COMMAND.search(policy_script)
                if not wrapped_command:
                    wrapped_command = _CORE_PLAIN_EVAL_COMMAND.search(policy_script)
                if wrapped_command:
                    cwd = _CORE_CWD.search(policy_script[: wrapped_command.start()])
                    policy_script = wrapped_command.group(1).replace("'\\''", "'")
                else:
                    cwd = _CORE_CWD.search(policy_script)
                    policy_script = _CORE_CWD.sub("", policy_script, count=1)
                if cwd and policy.refusal(cwd.group(1), policy_patterns[:4]):
                    refused = policy.refusal(cwd.group(1), policy_patterns[:4])
                elif job.get("file_op"):
                    refused = policy.refusal(policy_script, policy_patterns[:4])
                else:
                    refused = policy.refusal(policy_script, policy_patterns)
                if refused:
                    start_event.set()
                    receipt_outcome = "Refused by device policy"
                    self._result(job_id, seq, chunk=f"Policy refused command matching: {refused}\n", done=True, returncode=126)
                    return
                receipt_label = "Running a command"
                self._record_job_event(receipt_label, _command_text(script))
                exit_code = [0]
                capped = threading.Event()
                truncated = threading.Event()
                timeout = job.get("timeout", 120)
                self.job_deadlines[job_id] = time.monotonic() + timeout
                decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                def on_start(proc, started):
                    with self.process_lock:
                        self.processes[job_id] = (proc, started)
                        stopping = self.stop_event.is_set()
                        cancelled = job_id in self.cancelled_jobs or stopping
                        self.cancelled_jobs.discard(job_id)
                    if cancelled:
                        executor._terminate(proc, started)
                        if stopping:
                            executor._terminate_windows_jobs()
                    start_event.set()
                for chunk in executor.run(job["script"], login=job.get("login", False), timeout=timeout, job_id=job_id, stdin=job.get("stdin"), stdin_b64=job.get("stdin_b64"), on_start=on_start, on_exit=lambda code: exit_code.__setitem__(0, code), on_capped=capped.set, on_truncated=truncated.set):
                    with self.process_lock:
                        process = self.processes.get(job_id)
                    if process is not None and process[0].poll() is not None:
                        tail += chunk  # read after bash exited: it goes with done, in one result
                        if len(tail) < executor.CHUNK_SIZE:
                            continue
                        chunk, tail = tail, b""
                    self._result(job_id, seq, chunk=decoder.decode(chunk))
                    seq += 1
                final = decoder.decode(tail, final=True)
                if self._is_stopping():
                    returncode, error = self._stopped_result()
                    receipt_outcome = f"Stopped: {error}"
                    self._result(
                        job_id,
                        seq,
                        chunk=final,
                        done=True,
                        returncode=returncode,
                        error=error,
                    )
                elif capped.is_set():
                    receipt_outcome = "Failed: output limit reached"
                    self._result(job_id, seq, chunk=final, done=True, returncode=1, error="Output exceeded the 64 MiB device limit")
                elif truncated.is_set():
                    receipt_outcome = "Failed: output was truncated"
                    self._result(job_id, seq, chunk=final, done=True, returncode=1, error="Output was truncated after the post-exit pipe idle limit")
                else:
                    receipt_outcome = f"Completed with exit code {exit_code[0]}"
                    self._result(job_id, seq, chunk=final, done=True, returncode=exit_code[0])
            elif job_type == "checkup":
                self._record_job_event(receipt_label, "Started")
                result = checkup.collect()
                if self._is_stopping():
                    returncode, error = self._stopped_result()
                    receipt_outcome = f"Stopped: {error}"
                    self._result(job_id, seq, done=True, returncode=returncode, error=error)
                    return
                receipt_outcome = "Completed"
                receipt_timestamp = result["observed_at"]
                receipt_checkup = result
                self._result(
                    job_id,
                    seq,
                    done=True,
                    returncode=0,
                    error=None,
                    checkup=result,
                )
            elif job_type == "screenshot":
                self._record_job_event(receipt_label, "Started")
                if getattr(self, "witness", False):
                    if not self.allow_screen:
                        receipt_outcome = "Declined"
                        self._result(
                            job_id,
                            seq,
                            done=True,
                            returncode=126,
                            error="screenshot_declined",
                        )
                        return
                    answer = self.console_owner.request(
                        f"{self.instance}-screenshot-{job_id}",
                        SCREENSHOT_REQUEST_PROMPT,
                        timeout=_SCREENSHOT_REQUEST_TIMEOUT,
                    )
                    self._expire_session_if_due()
                    if self._is_stopping():
                        returncode, error = self._stopped_result()
                        receipt_outcome = f"Stopped: {error}"
                        self._result(
                            job_id,
                            seq,
                            done=True,
                            returncode=returncode,
                            error=error,
                        )
                        return
                    if self.stop_event.is_set():
                        receipt_label = None
                        return
                    if answer is None or answer.strip().casefold() != "y":
                        receipt_outcome = "Declined"
                        self._result(
                            job_id,
                            seq,
                            done=True,
                            returncode=126,
                            error="screenshot_declined",
                        )
                        return
                image = screen.capture(allow_screen=self.allow_screen)
                receipt_outcome = "Captured"
                self._result(job_id, seq, done=True, returncode=0, png=image)
            elif job_type == "cancel":
                self._record_job_event(receipt_label, "Started")
                with self.process_lock:
                    target = self.processes.get(job["target_job_id"])
                    if target is None:
                        self.cancelled_jobs.add(job["target_job_id"])
                        if len(self.cancelled_jobs) > 1024:
                            self.cancelled_jobs.pop()
                if target and target[0].poll() is None:
                    executor._terminate(target[0], target[1])
                receipt_outcome = "Cancellation request completed"
                self._result(job_id, seq, done=True, returncode=0)
        except InterruptedError:
            if receipt_outcome is None and receipt_label is not None:
                receipt_outcome = "Stopped before completion" if self._is_stopping() else "Interrupted before completion"
            return
        except PermissionError as exc:
            if str(exc) == "pairing_changed":
                receipt_label = None
                return
            if self._is_stopping():
                returncode, error = self._stopped_result()
                if receipt_outcome is None:
                    receipt_outcome = f"Stopped: {error}"
                try:
                    self._result(
                        job_id,
                        seq,
                        chunk=tail.decode("utf-8", errors="replace"),
                        done=True,
                        returncode=returncode,
                        error=error,
                    )
                except Exception:
                    logger.debug("Could not deliver stopped result for %s", job_id, exc_info=True)
                return
            if self.stop_event.is_set():
                logger.debug("Dropping result for %s because the device is stopping", job_id)
                receipt_label = None
                return
            if str(exc) == "unknown_device":
                return
            if str(exc) == "policy_changed":
                if receipt_outcome is None:
                    receipt_outcome = "Result delivery stopped after policy change"
                self._retry("poll_retry_delay", cap=5)
                return
            try:
                if receipt_outcome is None:
                    receipt_outcome = "Failed before completion"
                if tail:
                    self._result(job_id, seq, chunk=tail.decode("utf-8", errors="replace"))
                    seq += 1
                self._result(job_id, seq, done=True, returncode=1, error=str(exc))
            except Exception:
                logger.debug("Could not deliver job failure for %s", job_id, exc_info=True)
        except Exception as exc:
            if self._is_stopping():
                if receipt_outcome is None:
                    returncode, error = self._stopped_result()
                    receipt_outcome = f"Stopped: {error}"
                try:
                    returncode, error = self._stopped_result()
                    self._result(
                        job_id,
                        seq,
                        chunk=tail.decode("utf-8", errors="replace"),
                        done=True,
                        returncode=returncode,
                        error=error,
                    )
                except Exception:
                    logger.debug("Could not deliver stopped result for %s", job_id, exc_info=True)
                return
            if self.stop_event.is_set():
                logger.debug("Dropping result for %s because the device is stopping", job_id)
                receipt_label = None
                return
            try:
                if receipt_outcome is None:
                    receipt_outcome = "Failed before completion"
                if tail:
                    self._result(job_id, seq, chunk=tail.decode("utf-8", errors="replace"))
                    seq += 1
                self._result(job_id, seq, done=True, returncode=1, error=str(exc))
            except Exception:
                logger.debug("Could not deliver job failure for %s", job_id, exc_info=True)
        finally:
            if receipt_label is not None and receipt_outcome is not None:
                self._record_job_event(
                    receipt_label,
                    receipt_outcome,
                    timestamp=receipt_timestamp,
                    checkup_result=receipt_checkup,
                )
            start_event.set()
            with self.process_lock:
                self.processes.pop(job_id, None)
                self.job_start_events.pop(job_id, None)
                self.cancelled_jobs.discard(job_id)
            self.running.pop(job_id, None)
            self.job_deadlines.pop(job_id, None)

    def _heartbeat_loop(self) -> None:
        if not hasattr(self, "heartbeat_retry_delay"):
            self.heartbeat_retry_delay = 1
        if not hasattr(self, "heartbeat_lock"):
            self.heartbeat_lock = threading.Lock()
        while not self.stop_event.is_set():
            try:
                with self.heartbeat_lock:
                    if self.stop_event.is_set():
                        return
                    response = self._post("/device/heartbeat", self._heartbeat_body())
                    self._verify_response(response, "/device/heartbeat")
                self.heartbeat_retry_delay = 1
                self.stop_event.wait(5)
            except PermissionError as exc:
                if str(exc) == "pairing_changed":
                    return
                if str(exc) == "unknown_device":
                    self.stop_event.set()
                    return
                if str(exc) == "policy_changed":
                    self._retry("heartbeat_retry_delay", cap=5)
                    continue
                self._retry("heartbeat_retry_delay")
            except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError):
                self._retry("heartbeat_retry_delay")

    def run_forever(self) -> None:
        if not hasattr(self, "poll_retry_delay"):
            self.poll_retry_delay = 1
        if getattr(self, "witness", False) and getattr(self, "session_state", "normal") == "active":
            if getattr(self, "session_started_at", None) is None:
                self.session_started_at = _utc_timestamp()
                self._record_receipt_event("Witness session", "Started after consent")
            if getattr(self, "session_deadline", None) is None:
                self.session_deadline = time.monotonic() + _WITNESS_SESSION_SECONDS
        lock_path = Path.home() / ".hermes-hands" / "serve.lock"
        lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_file = lock_path.open("a+b")
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b"\0")
            lock_file.flush()
        lock_file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            lock_file.close()
            raise RuntimeError("Another hermes-hands serve process is already running for this device home") from exc
        screenshot_consent_thread = None
        help_thread = None
        try:
            executor.reap_recorded_processes()
            heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
            heartbeat.start()
            if getattr(self, "witness", False):
                help_thread = threading.Thread(
                    target=self._help_loop,
                    name="hermes-hands-help-client",
                    daemon=True,
                )
                help_thread.start()
                screenshot_consent_thread = threading.Thread(
                    target=self._request_session_screenshot_consent,
                    name="hermes-hands-screenshot-consent",
                    daemon=True,
                )
                screenshot_consent_thread.start()
            while not self.stop_event.is_set():
                if self._expire_session_if_due():
                    break
                try:
                    response = self._post("/device/poll", self._poll_body())
                    job = self._verify_response(response, "/device/poll")
                    if self._expire_session_if_due():
                        break
                    if self.fatal:
                        raise self.fatal[0]
                    if job:
                        if not hasattr(self, "process_lock"):
                            self.process_lock = threading.Lock()
                        if not hasattr(self, "job_start_events"):
                            self.job_start_events = {}
                        start_event = threading.Event()
                        thread = threading.Thread(target=self._run_job, args=(job, start_event), daemon=True)
                        with self.process_lock:
                            if not self.stop_event.is_set():
                                self.job_start_events[job["job_id"]] = start_event
                                self.running[job["job_id"]] = thread
                                thread.start()
                    self.poll_retry_delay = 1
                    if self.fatal:
                        raise self.fatal[0]
                except InterruptedError:
                    if self._is_stopping():
                        break
                    raise
                except PermissionError as exc:
                    if str(exc) == "pairing_changed":
                        raise RuntimeError("Device pairing changed while serve was running") from exc
                    if str(exc) == "unknown_device":
                        raise
                    if str(exc) == "policy_changed":
                        self._retry("poll_retry_delay", cap=5)
                        continue
                    self._retry("poll_retry_delay")
                except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError) as exc:
                    if self._expire_session_if_due():
                        break
                    if not (isinstance(exc, ValueError) and str(exc).startswith("transient relay status ")):
                        logger.warning("Device poll failed; retrying")
                    self._retry("poll_retry_delay")
        except KeyboardInterrupt:
            self._begin_stopping()
            raise
        finally:
            console_owner = getattr(self, "console_owner", None)
            if console_owner is not None:
                console_owner.close()
                console_owner.join(0.1)
            if screenshot_consent_thread is not None:
                screenshot_consent_thread.join(0.1)
            if self._is_stopping():
                self._stop_and_flush()
            else:
                self.stop_event.set()
                self._cancel_running_jobs()
            if help_thread is not None:
                help_thread.join(0.1)
            if os.name == "nt":
                import msvcrt

                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()


