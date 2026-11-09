"""The relay: per-device job queues, long-polls, ordered results and signed replies.

It lives in the ``hermes dashboard`` process only: ``dashboard/plugin_api.py`` calls :func:`serve` on
the first request, and only when ``app.state.gateway_runner`` is None. Replies to an authenticated
device are signed R2D with the relay key; the R2D nonce is the request's bearer nonce, which binds a
reply to the request it answers. Refusals to callers that proved no key are unsigned. ``/local/*``
serves the gateway's loopback client (``client.py``). Framework-free: handlers take ``(principal,
headers, path, body)``, device routes also the client address ``peer``, and return a :class:`Reply`.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import messages, protocol, store

PROVIDER = "hermes-hands"
API = "/api/plugins/hermes-hands"
TOKEN_ROUTES = tuple(
    API + route
    for route in (
        "/pair",
        "/device/poll",
        "/device/result",
        "/device/heartbeat",
        "/device/help",
        "/local/exec",
        "/local/output",
        "/local/cancel",
        "/local/state",
    )
)
SCOPE_PAIR = "hands:pair"
SCOPE_DEVICE = "hands:device"
SCOPE_REVOKED = "hands:revoked"  # a fresh bearer signed by a revoked device's key
SCOPE_LOCAL = "hands:local"

UNREACHABLE = 255  # the gateway's own exit code; its hands: line says whether anything ran
CANCELLED = 137
MAX_POLL_WAIT = 25
MAX_OUTPUT_WAIT = 20
MAX_JOB_TEXT = 16_000_000  # characters in an exec job's script, and in its stdin
MAX_PNG_BYTES = 2 * 1024 * 1024
_MAX_PNG_B64 = 4 * -(-MAX_PNG_BYTES // 3)
MAX_HELP_BODY_BYTES = 8192
_LIVENESS_EVERY = 1.0
_ABANDONED_AFTER = 60  # seconds without a gateway fetch: the caller is gone, cancel the job
_HEARTBEAT_EVERY = 5
_INSTANCE_QUIET = (
    10  # seconds without contact before a job's agent counts as gone (it heartbeats every 5)
)
_INSTANCE_FORGOTTEN = 60  # seconds before a silent agent instance is no longer remembered
_SESSION_STATES = {"normal", "active", "stopping", "stopped"}
_STOPPING_STATES = {"stopping", "stopped"}
_CAPABILITIES = {"witness-v1", "checkup-v1", "help-v1", "receipt-v1"}

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Keys:
    """Everything derived from ``HANDS_RELAY_SEED``: the relay's Ed25519 key pair and the local bearer."""

    relay_private: bytes
    relay_public: bytes
    local_bearer: str


def derive_keys(seed: str) -> Keys:
    """HKDF-SHA256 over the seed, one label per key, so both processes derive the same keys."""

    def _hkdf(label: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(
            seed.encode("utf-8")
        )

    private = _hkdf(b"hermes-hands/relay-signing-key")
    public = (
        Ed25519PrivateKey.from_private_bytes(private)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return Keys(private, public, protocol.b64u(_hkdf(b"hermes-hands/local-bearer")))


@dataclass
class Reply:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    # Set when the device list changed (paired, newly refused): plugin_api.py broadcasts it as
    # ``plugin.hermes-hands.devices.changed`` so the Desktop pane refreshes before its next poll.
    devices_changed: dict | None = None

    @classmethod
    def json(cls, status: int, obj: dict) -> "Reply":
        return cls(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"))


@dataclass
class _Job:
    job_id: str
    device_id: str
    device_name: str
    job_type: str = "exec"
    chunks: dict[int, str] = field(default_factory=dict)  # by device seq, not yet handed out
    received: int = 0  # device seqs 0..received-1 have all arrived
    final_seq: int | None = None
    returncode: int | None = None
    error: str | None = None
    png_b64: str | None = None
    checkup: dict | None = None
    done: bool = False
    picked: bool = False
    instance: str | None = None  # the agent process that picked it, when the poll named one
    last_fetch: float = field(default_factory=time.monotonic)


def _has(principal, scope: str) -> bool:
    return (
        principal is not None
        and getattr(principal, "provider", None) == PROVIDER
        and scope in getattr(principal, "scopes", ())
    )


def _bearer(headers) -> str:
    scheme, _, token = headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.strip().lower() == "bearer" else ""


def _optional_string(request: dict, key: str) -> str | None:
    if key not in request:
        return None
    value = request[key]
    if not isinstance(value, str):
        raise ValueError(key)
    return value


def _required_string(request: dict, key: str) -> str:
    value = request.get(key)
    if not isinstance(value, str):
        raise ValueError(key)
    return value


def _help_text(value: str) -> str:
    cleaned = "".join(
        character for character in value.strip() if unicodedata.category(character) != "Cc"
    )[:200]
    if not cleaned:
        raise ValueError("text")
    return cleaned


def _witness_fields(request: dict) -> tuple[bool, str, list[str]]:
    if "witness" not in request:
        state = request.get("session_state", "normal")
        capabilities = request.get("capabilities", [])
        if not isinstance(state, str) or state not in _SESSION_STATES:
            raise ValueError("session_state")
        if not isinstance(capabilities, list) or any(
            not isinstance(capability, str) or capability not in _CAPABILITIES
            for capability in capabilities
        ):
            raise ValueError("capabilities")
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("duplicate capability")
        return False, "normal", []

    witness = request["witness"]
    state = request.get("session_state")
    capabilities = request.get("capabilities")
    if type(witness) is not bool:
        raise ValueError("witness")
    if not isinstance(state, str) or state not in _SESSION_STATES:
        raise ValueError("session_state")
    if not isinstance(capabilities, list) or any(
        not isinstance(capability, str) or capability not in _CAPABILITIES
        for capability in capabilities
    ):
        raise ValueError("capabilities")
    if len(capabilities) != len(set(capabilities)):
        raise ValueError("duplicate capability")
    if (state == "active") != witness and state not in _STOPPING_STATES:
        raise ValueError("witness session_state")
    return witness, state, capabilities


def _pairing_detail(exc: store.PairingError) -> str:
    if exc.error == "name_taken":
        return messages.pair_name_taken(exc.name)
    if exc.error == "name_mismatch":
        return messages.pair_name_mismatch(exc.name)
    if exc.error == "name_reserved":
        return messages.PAIR_NAME_RESERVED
    return messages.PAIR_BAD_CODE


class Relay:
    def __init__(self, keys: Keys):
        self._keys = keys
        self._lock = threading.Lock()
        self._jobs: dict[str, _Job] = {}
        self._queues: dict[str, deque] = {}
        self._nonces = protocol.NonceCache()
        self._refused: set[str] = set()  # devices currently refused for a changed deny-list
        # device id -> {agent instance: last contact (monotonic)}
        self._instances: dict[str, dict[str, float]] = {}
        # (device id, agent instance or None) -> generation of that agent's newest poll
        self._polls: dict[tuple[str, str | None], int] = {}
        # Long-polls waiting for a change, by device id (a queued job) or job id (output, the end).
        self._waiters: dict[str, set[tuple[asyncio.AbstractEventLoop, asyncio.Future]]] = {}

    # --- lifecycle -----------------------------------------------------------------------------
    def start(self) -> None:
        """Write the first liveness row before this relay answers its first request, so a caller
        can read ``store.relay_alive`` right after it; a daemon thread keeps the row fresh."""
        self._beat()
        threading.Thread(
            target=self._heartbeat_loop, name="hermes-hands-relay", daemon=True
        ).start()

    def _heartbeat_loop(self) -> None:
        while True:
            time.sleep(_HEARTBEAT_EVERY)
            self._beat()

    def _beat(self) -> None:
        """Write the liveness row the gateway reads (``store.relay_alive``) and reap abandoned jobs."""
        try:
            store.write_relay_heartbeat()
        except sqlite3.Error:
            logger.warning("hermes-hands: could not write the relay heartbeat", exc_info=True)
        self._reap()

    def _reap(self) -> None:
        """Cancel and drop jobs nobody has fetched for ``_ABANDONED_AFTER`` seconds."""
        cutoff = time.monotonic() - _ABANDONED_AFTER
        with self._lock:
            for job in [j for j in self._jobs.values() if j.last_fetch < cutoff]:
                self._cancel_locked(job)
                del self._jobs[job.job_id]

    # --- signing and job bookkeeping (caller holds no lock unless named *_locked) ----------------
    def _signed(self, status: int, obj: dict, path: str, nonce: str | None = None) -> Reply:
        body = protocol.canonical_json(obj)
        ts, nonce = int(time.time()), nonce or protocol.new_nonce()
        signature = protocol.sign_request(
            self._keys.relay_private, protocol.R2D, ts, nonce, "POST", path, body
        )
        return Reply(
            status,
            body,
            {"X-Hands-Ts": str(ts), "X-Hands-Nonce": nonce, "X-Hands-Signature": signature},
        )

    def _finish_locked(self, job: _Job, returncode: int, error: str) -> None:
        """End ``job`` for any reason but the device's own done; a job the device picked up is
        also cancelled there, so abandoned work never keeps running on the device. A job it never
        picked up leaves the queue now, so a device that never polls again holds no payload."""
        job.done, job.returncode, job.error = True, returncode, error
        self._wake_locked(job.job_id)
        queue = self._queues.setdefault(job.device_id, deque())
        if job.picked and self._accepting_work_locked(job.device_id):
            cancel = {"job_id": secrets.token_hex(8), "type": "cancel", "target_job_id": job.job_id}
            queue.append(cancel)
            self._wake_locked(job.device_id)
        else:
            for payload in [q for q in queue if q["job_id"] == job.job_id]:
                queue.remove(payload)
        if not queue:
            del self._queues[job.device_id]

    def _accepting_work_locked(self, device_id: str) -> bool:
        device = store.device_by_id(device_id)
        return device is not None and device["session_state"] not in _STOPPING_STATES

    def _stop_device_locked(self, device_id: str) -> None:
        """Fail queued work and wake parked polls after the stored session enters STOPPING."""
        self._supersede_polls_locked(device_id, [instance for dev, instance in self._polls if dev == device_id])
        self._queues.pop(device_id, None)
        for job in self._jobs.values():
            if job.device_id == device_id and not job.done and not job.picked:
                job.done, job.returncode, job.error = True, 130, "stopped_by_person"
                self._wake_locked(job.job_id)

    def _record_seen(self, device_id: str, **fields) -> tuple[bool | None, dict | None]:
        """Persist a signed device update and stop queued work under the same relay lock."""
        with self._lock:
            ok = store.record_seen(device_id, **fields)
            saved = store.device_by_id(device_id)
            if saved is not None and saved["session_state"] in _STOPPING_STATES:
                self._stop_device_locked(device_id)
            return ok, saved

    def _cancel_locked(self, job: _Job) -> None:
        if not job.done:
            self._finish_locked(job, CANCELLED, messages.cancelled(job.device_name))

    def _fail_device(self, device_id: str, name: str) -> None:
        """Fail every job of a device refused for a changed deny-list and end its parked polls: a
        poll that began before this refusal must not hand out a job, which would tell the device its
        old hash is accepted. Its queue stays: finished jobs are never handed out (``_pop_locked``),
        and the cancels for the picked ones must still reach it."""
        with self._lock:
            self._supersede_polls_locked(device_id, [i for d, i in self._polls if d == device_id])
            for job in self._jobs.values():
                if job.device_id == device_id and not job.done:
                    error = (
                        messages.policy_changed_while_running
                        if job.picked
                        else messages.policy_changed
                    )
                    self._finish_locked(job, UNREACHABLE, error(name))

    def _pop_locked(self, device_id: str, instance: str | None) -> dict | None:
        queue = self._queues.get(device_id)
        while queue:
            payload = queue.popleft()
            if payload["type"] == "cancel":
                return payload
            job = self._jobs.get(payload["job_id"])
            if job is not None and not job.done:
                job.picked, job.instance = True, instance
                return payload
        return None

    # --- long-poll wakeups --------------------------------------------------------------------
    def _waiter_locked(self, key: str) -> tuple[asyncio.AbstractEventLoop, asyncio.Future]:
        """Register a wait on ``key`` in the same lock hold as the caller's check of the state it
        waits for, so a change made after that check always wakes it. The future belongs to the
        caller's own event loop (the dashboard's, or one per request under a test client), and any
        thread wakes it through that loop."""
        loop = asyncio.get_running_loop()
        waiter = (loop, loop.create_future())
        self._waiters.setdefault(key, set()).add(waiter)
        return waiter

    async def _wait(self, key: str, waiter, timeout: float) -> None:
        """Until ``key`` is woken or ``timeout`` passes; the caller then checks the state again."""
        try:
            await asyncio.wait([waiter[1]], timeout=timeout)
        finally:
            with self._lock:
                waiting = self._waiters.get(key)
                if waiting is not None:
                    waiting.discard(waiter)
                    if not waiting:
                        del self._waiters[key]

    def _wake_locked(self, key: str) -> None:
        for loop, future in self._waiters.pop(key, ()):
            try:
                loop.call_soon_threadsafe(future.set_result, None)
            except RuntimeError:
                pass  # that loop has closed, so nothing waits there any more

    def _take_locked(self, job: _Job, after: int) -> dict:
        """Chunks from seq ``after`` on (older ones are freed). A done job stays until ``_reap``, so a
        fetch whose reply was lost gets the same final chunks and exit code again."""
        for seq in [s for s in job.chunks if s < after]:
            del job.chunks[seq]
        output = {
            "chunks": [job.chunks[s] for s in range(after, job.received)],
            "next": max(after, job.received),
            "done": job.done,
            "returncode": job.returncode if job.done else None,
            "error": job.error if job.done else None,
            "png_b64": job.png_b64 if job.done else None,
        }
        if job.done and job.checkup is not None:
            output["checkup"] = job.checkup
        return output

    def _check_device(self, job: _Job) -> None:
        """Fail a job whose device was revoked, went offline or changed its deny-list, or whose agent
        process is gone. The message says whether it may have run: only a picked job can have."""
        device = store.device_by_id(job.device_id)
        with self._lock:
            if job.done:
                return
            name, picked = job.device_name, job.picked
            if device is None:
                error = (messages.revoked if picked else messages.unknown_device)(name)
                self._finish_locked(job, UNREACHABLE, error)
                self._queues.pop(job.device_id, None)  # a revoked device never polls again
                return
            if not device["policy_ok"]:
                error = (
                    messages.policy_changed_while_running if picked else messages.policy_changed
                )(name)
            elif not device["online"]:
                error = (messages.went_offline if picked else messages.offline)(name)
            elif self._agent_gone_locked(job):
                error = messages.agent_restarted(name)
            else:
                return
            self._finish_locked(job, UNREACHABLE, error)

    def _agent_gone_locked(self, job: _Job) -> bool:
        """The agent process that picked ``job`` fell quiet while another one for the device kept in
        touch: it restarted or died, so the job will never report."""
        if not job.picked or job.instance is None:
            return False
        seen = self._instances.get(job.device_id, {})
        last = seen.get(job.instance, float("-inf"))
        return time.monotonic() - last > _INSTANCE_QUIET and any(
            contact >= last for instance, contact in seen.items() if instance != job.instance
        )

    # --- device routes -------------------------------------------------------------------------
    def _device(self, principal, headers, path: str, body: bytes, peer: str):
        """``(device, bearer nonce, None)`` for a verified device request, else ``(None, None, reply)``.
        The token provider checked the bearer's signature and freshness; this checks the request
        signature (X-Hands-Signature) over the same ts and nonce, and only then burns the nonce, so a
        caller without the device key cannot burn one. ``NonceCache.check_and_add`` is atomic, so of
        two concurrent copies of one request exactly one gets through. A revoked device (also one
        revoked after the token seam ran) proves its tombstoned key the same way and then gets the
        signed ``unknown_device``. Other refusals here are unsigned: a caller that has not proven a
        device key never gets a relay signature."""
        bearer = protocol.parse_bearer(_bearer(headers))
        if (
            not (_has(principal, SCOPE_DEVICE) or _has(principal, SCOPE_REVOKED))
            or bearer is None
            or bearer.device_id != principal.principal
        ):
            return (
                None,
                None,
                Reply.json(401, {"error": "unauthenticated", "detail": messages.UNAUTHENTICATED}),
            )
        device = store.device_by_id(bearer.device_id)
        public_key = store.revoked_key(bearer.device_id) if device is None else device["public_key"]
        if public_key is None or not protocol.verify_request(
            public_key,
            headers.get("x-hands-signature", ""),
            protocol.D2R,
            bearer.ts,
            bearer.nonce,
            "POST",
            path,
            body,
        ):
            return (
                None,
                None,
                Reply.json(401, {"error": "bad_signature", "detail": messages.UNAUTHENTICATED}),
            )
        if not self._nonces.check_and_add(bearer.nonce, int(time.time())):
            return None, None, Reply.json(401, {"error": "replayed", "detail": messages.REPLAYED})
        if device is None:
            store.mark_told(bearer.device_id)  # it is told again until STOP_GRACE has passed
            return None, None, self._unknown(bearer.device_id, path, bearer.nonce, peer)
        return device, bearer.nonce, None

    def _unknown(self, device_id: str, path: str, nonce: str, peer: str) -> Reply:
        """The signed ``401 unknown_device`` that stops a revoked device, which proved its key; logged
        here because the token seam writes no audit row for a principal it let through."""
        logger.warning(
            "hermes-hands: revoked device %s called from %s; told it to stop", device_id, peer
        )
        return self._signed(
            401, {"error": "unknown_device", "detail": messages.UNKNOWN_DEVICE_WIRE}, path, nonce
        )

    def _supersede_polls_locked(self, device_id: str, instances) -> None:
        """End the device's polls parked here for these agent instances (each returns 204)."""
        for instance in instances:
            key = (device_id, instance)
            self._polls[key] = self._polls.get(key, 0) + 1
        self._wake_locked(device_id)

    def _note_instance(self, device: dict, instance: str | None) -> None:
        """Record contact from an agent process. The first contact from a new one ends the other
        processes' parked polls once: after a restart they are dead connections. Agents that are all
        alive never end each other's polls again, so two agents for one device cannot set off a
        poll storm, and their jobs are left alone. A job whose agent fell quiet is failed by
        ``_check_device``."""
        if instance is None:
            return
        device_id, now = device["device_id"], time.monotonic()
        with self._lock:
            seen = self._instances.setdefault(device_id, {})
            new = instance not in seen
            seen[instance] = now
            for gone in [i for i, contact in seen.items() if now - contact > _INSTANCE_FORGOTTEN]:
                del seen[gone]
                self._polls.pop((device_id, gone), None)
            if new and len(seen) > 1:
                others = [i for d, i in self._polls if d == device_id and i != instance]
                self._supersede_polls_locked(device_id, others)

    def _seen_refusal(
        self, ok: bool | None, device: dict, path: str, nonce: str, peer: str
    ) -> Reply | None:
        """The reply for a device whose ``record_seen`` came back unknown or policy-refused, else None."""
        if ok is None:
            return self._unknown(device["device_id"], path, nonce, peer)
        if not ok:
            self._fail_device(device["device_id"], device["name"])
            reply = self._signed(
                409,
                {"error": "policy_changed", "detail": messages.POLICY_CHANGED_WIRE},
                path,
                nonce,
            )
            with self._lock:
                newly = device["device_id"] not in self._refused
                self._refused.add(device["device_id"])
            if newly:
                reply.devices_changed = {"reason": "policy_changed", "device": device["name"]}
            return reply
        with self._lock:
            self._refused.discard(device["device_id"])
        return None

    async def pair(self, principal, headers, path: str, body: bytes) -> Reply:
        if not _has(principal, SCOPE_PAIR):
            return Reply.json(401, {"error": "bad_code", "detail": messages.PAIR_BAD_CODE})
        try:
            request = json.loads(body)
            fields = {k: v for k, v in request.items() if k != "sig"}
            public_key = protocol.unb64u(request["public_key"])
            signature = protocol.unb64u(request["sig"])
            name, device_os, home, policy_hash, version = (
                str(request[k]) for k in ("name", "os", "home", "policy_hash", "protocol")
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._signed(400, {"error": "bad_request", "detail": messages.BAD_REQUEST}, path)
        if version != protocol.PROTOCOL_VERSION:
            return self._signed(
                426,
                {
                    "error": "protocol_mismatch",
                    "detail": messages.protocol_mismatch(version),
                    "upgrade": messages.UPGRADE,
                },
                path,
            )
        if not protocol.verify(public_key, signature, protocol.canonical_json(fields)):
            return self._signed(
                401, {"error": "bad_signature", "detail": messages.PAIR_BAD_SIGNATURE}, path
            )
        owner_label = await asyncio.to_thread(
            store.pairing_code_owner_label, _bearer(headers)
        )
        try:
            device_id = await asyncio.to_thread(
                store.complete_pairing,
                _bearer(headers),
                name=name,
                public_key=request["public_key"],
                os=device_os,
                home=home,
                policy_hash=policy_hash,
            )
        except store.PairingError as exc:
            return self._signed(
                exc.status, {"error": exc.error, "detail": _pairing_detail(exc)}, path
            )
        response = {
            "device_id": device_id,
            "relay_public_key": protocol.b64u(self._keys.relay_public),
        }
        if owner_label is not None:
            response["owner_label"] = owner_label
        reply = self._signed(
            200,
            response,
            path,
        )
        reply.devices_changed = {"reason": "paired", "device": name}
        return reply

    async def device_poll(self, principal, headers, path: str, body: bytes, peer: str) -> Reply:
        """Long-poll for the device's next job. Only an agent's newest poll can take one: an older
        poll of the same agent still parked here belongs to a connection it dropped (a network
        change), so it returns 204 instead of handing a job to nobody."""
        device, nonce, refusal = await asyncio.to_thread(
            self._device, principal, headers, path, body, peer
        )
        if refusal is not None:
            return refusal
        try:
            request = json.loads(body)
            if not isinstance(request, dict) or type(request.get("wait")) is not int:
                raise ValueError("wait")
            wait = min(max(request["wait"], 0), MAX_POLL_WAIT)
            instance = _optional_string(request, "instance")
            policy_hash = _optional_string(request, "policy_hash")
            witness, session_state, capabilities = _witness_fields(request)
        except (ValueError, TypeError, AttributeError):
            return self._signed(
                400, {"error": "bad_request", "detail": messages.BAD_REQUEST}, path, nonce
            )
        ok, _ = await asyncio.to_thread(
            self._record_seen,
            device["device_id"],
            policy_hash=policy_hash,
            instance=instance,
            witness=witness,
            session_state=session_state,
            capabilities=capabilities,
        )
        refusal = self._seen_refusal(ok, device, path, nonce, peer)
        if refusal is not None:
            return refusal
        self._note_instance(device, instance)
        device_id, deadline = device["device_id"], time.monotonic() + wait
        with self._lock:
            saved = store.device_by_id(device_id)
            if saved is None or saved["session_state"] in _STOPPING_STATES:
                return Reply(204)
            self._supersede_polls_locked(device_id, [instance])
            generation = self._polls[(device_id, instance)]
        while True:
            with self._lock:
                newest = self._polls.get((device_id, instance)) == generation
                job = self._pop_locked(device_id, instance) if newest else None
                remaining = deadline - time.monotonic()
                waiter = (
                    None
                    if job is not None or not newest or remaining <= 0
                    else self._waiter_locked(device_id)
                )
            if job is not None:
                return self._signed(200, job, path, nonce)
            if waiter is None:
                return Reply(204)
            await self._wait(device_id, waiter, remaining)

    async def device_help(self, principal, headers, path: str, body: bytes, peer: str) -> Reply:
        """Accept a bounded help message from the currently witnessed paired device."""
        device, nonce, refusal = await asyncio.to_thread(
            self._device, principal, headers, path, body, peer
        )
        if refusal is not None:
            return refusal
        if len(body) > MAX_HELP_BODY_BYTES:
            return self._signed(
                413, {"error": "too_large", "detail": messages.BAD_REQUEST}, path, nonce
            )
        try:
            request = json.loads(body)
            if (
                not isinstance(request, dict)
                or set(request) != {"request_id", "instance", "text"}
                or not isinstance(request["request_id"], str)
                or re.fullmatch(r"[0-9a-f]{32}", request["request_id"]) is None
                or not isinstance(request["instance"], str)
                or not request["instance"]
                or not isinstance(request["text"], str)
            ):
                raise ValueError("help request")
            text = _help_text(request["text"])
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._signed(
                400, {"error": "bad_request", "detail": messages.BAD_REQUEST}, path, nonce
            )

        result = await asyncio.to_thread(
            store.accept_help_request,
            device["device_id"],
            request_id=request["request_id"],
            instance=request["instance"],
            text=text,
        )
        if result == "unknown_device":
            return self._unknown(device["device_id"], path, nonce, peer)
        if result in {"accepted", "duplicate"}:
            return self._signed(
                200, {"request_id": request["request_id"], "status": "accepted"}, path, nonce
            )
        if result == "rate_limited":
            return self._signed(
                429,
                {"error": "rate_limited", "detail": "hands: this witness session reached its help limit."},
                path,
                nonce,
            )
        if result == "unsupported_capability":
            return self._signed(
                409,
                {"error": "unsupported_capability", "detail": "hands: this device does not advertise help-v1."},
                path,
                nonce,
            )
        if result == "owner_origin_required":
            return self._signed(
                409,
                {"error": "owner_origin_required", "detail": "hands: select this device from an owner direct message first."},
                path,
                nonce,
            )
        return self._signed(
            409,
            {"error": "witness_inactive", "detail": "hands: this device has no active witness session."},
            path,
            nonce,
        )

    async def device_result(self, principal, headers, path: str, body: bytes, peer: str) -> Reply:
        device, nonce, refusal = await asyncio.to_thread(
            self._device, principal, headers, path, body, peer
        )
        if refusal is not None:
            return refusal
        try:
            result = json.loads(body)
            if not isinstance(result, dict):
                raise ValueError("body")
            job_id = _required_string(result, "job_id")
            seq = result.get("seq")
            chunk = _required_string(result, "chunk")
            done = result.get("done")
            policy_hash = _required_string(result, "policy_hash")
            if type(seq) is not int or seq < 0 or type(done) is not bool:
                raise ValueError("bad seq")
            if done:
                returncode = result.get("returncode")
                error = result.get("error")
                if (
                    type(returncode) is not int
                    or ("error" not in result and device["capabilities"])
                    or (error is not None and not isinstance(error, str))
                ):
                    raise ValueError("bad final result")
            elif "returncode" in result or "error" in result:
                raise ValueError("non-final result has final fields")
            else:
                returncode, error = None, None
            png_b64 = result.get("png_b64")
            if "png_b64" in result and (not done or not isinstance(png_b64, str)):
                raise ValueError("bad png_b64")
            has_checkup = "checkup" in result
            checkup = result.get("checkup")
            if has_checkup and (not done or not isinstance(checkup, dict)):
                raise ValueError("bad checkup")
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._signed(
                400, {"error": "bad_request", "detail": messages.BAD_REQUEST}, path, nonce
            )
        ok, _ = await asyncio.to_thread(
            self._record_seen, device["device_id"], policy_hash=policy_hash
        )
        refusal = self._seen_refusal(ok, device, path, nonce, peer)
        if refusal is not None:
            return refusal
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.device_id != device["device_id"] or job.done:
                return self._signed(200, {"ok": True, "cancel": True}, path, nonce)
            if (has_checkup and job.job_type != "checkup") or (
                job.job_type == "checkup" and png_b64 is not None
            ):
                return self._signed(
                    400, {"error": "bad_request", "detail": messages.BAD_REQUEST}, path, nonce
                )
            if png_b64 is not None and len(png_b64) > _MAX_PNG_B64:
                self._finish_locked(job, UNREACHABLE, messages.SCREENSHOT_TOO_LARGE)
                return self._signed(
                    413,
                    {"error": "too_large", "detail": messages.SCREENSHOT_TOO_LARGE},
                    path,
                    nonce,
                )
            if seq >= job.received and seq not in job.chunks:
                job.chunks[seq] = chunk
                if done:
                    job.final_seq, job.returncode = seq, returncode
                    job.error, job.png_b64, job.checkup = error, png_b64, checkup
                while job.received in job.chunks:
                    job.received += 1
                if job.final_seq is not None and job.received > job.final_seq:
                    job.done = True
                self._wake_locked(job_id)
        return self._signed(200, {"ok": True, "cancel": False}, path, nonce)

    async def device_heartbeat(
        self, principal, headers, path: str, body: bytes, peer: str
    ) -> Reply:
        device, nonce, refusal = await asyncio.to_thread(
            self._device, principal, headers, path, body, peer
        )
        if refusal is not None:
            return refusal
        try:
            beat = json.loads(body)
            if not isinstance(beat, dict):
                raise ValueError("body")
            policy_hash = _required_string(beat, "policy_hash")
            device_os = _required_string(beat, "os")
            home = _required_string(beat, "home")
            agent_version = _required_string(beat, "agent_version")
            instance = _optional_string(beat, "instance")
            witness, session_state, capabilities = _witness_fields(beat)
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._signed(
                400, {"error": "bad_request", "detail": messages.BAD_REQUEST}, path, nonce
            )
        ok, _ = await asyncio.to_thread(
            self._record_seen,
            device["device_id"],
            policy_hash=policy_hash,
            os=device_os,
            home=home,
            agent_version=agent_version,
            instance=instance,
            witness=witness,
            session_state=session_state,
            capabilities=capabilities,
        )
        refusal = self._seen_refusal(ok, device, path, nonce, peer)
        if refusal is not None:
            return refusal
        self._note_instance(device, instance)
        return self._signed(200, {"ok": True}, path, nonce)

    # --- local routes (gateway loopback client) ------------------------------------------------
    @staticmethod
    def _local_refusal(principal, headers) -> Reply | None:
        if "x-forwarded-for" in headers or "forwarded" in headers:
            return Reply.json(403, {"error": "forwarded", "detail": messages.FORWARDED})
        if not _has(principal, SCOPE_LOCAL):
            return Reply.json(401, {"error": "unauthenticated", "detail": messages.UNAUTHENTICATED})
        return None

    async def local_exec(self, principal, headers, path: str, body: bytes) -> Reply:
        refusal = self._local_refusal(principal, headers)
        if refusal is not None:
            return refusal
        try:
            request = json.loads(body)
            if not isinstance(request, dict):
                raise ValueError("body")
            name, kind = str(request["device"]), str(request.get("type", "exec"))
            if kind == "exec":
                extra = {
                    "script": str(request["script"]),
                    "login": bool(request.get("login", False)),
                    "timeout": int(request["timeout"]),
                }
                stdin_text = request.get("stdin", None)
                stdin_b64 = request.get("stdin_b64", None)
                if stdin_text is not None and stdin_b64 is not None:
                    raise ValueError("stdin and stdin_b64")
                file_op = request.get("file_op", False)
                if not isinstance(file_op, bool):
                    raise ValueError("file_op")
                if stdin_b64 is not None:
                    if not isinstance(stdin_b64, str):
                        raise ValueError("stdin_b64")
                    if len(stdin_b64) > 4 * -(-MAX_JOB_TEXT // 3):
                        return Reply.json(
                            413, {"error": "too_large", "detail": messages.JOB_TOO_LARGE}
                        )
                    if len(base64.b64decode(stdin_b64, validate=True)) > MAX_JOB_TEXT:
                        return Reply.json(
                            413, {"error": "too_large", "detail": messages.JOB_TOO_LARGE}
                        )
                    extra["stdin_b64"] = stdin_b64
                elif stdin_text is not None:
                    if not isinstance(stdin_text, str):
                        raise ValueError("stdin")
                    extra["stdin"] = stdin_text
                extra["file_op"] = file_op
            elif kind == "checkup":
                if set(request) != {"device", "type"}:
                    raise ValueError("checkup arguments")
                extra = {}
            elif kind == "screenshot":
                extra = {}
            else:
                raise ValueError(f"unknown job type {kind!r}")
        except (ValueError, KeyError, TypeError, AttributeError):
            return Reply.json(400, {"error": "bad_request", "detail": messages.BAD_REQUEST})
        if any(len(extra.get(key, "")) > MAX_JOB_TEXT for key in ("script", "stdin")):
            return Reply.json(413, {"error": "too_large", "detail": messages.JOB_TOO_LARGE})
        job_id = secrets.token_hex(8)
        payload = {"job_id": job_id, "type": kind, **extra}
        with self._lock:
            device = store.get_device(name)
            if device is None:
                return Reply.json(
                    404, {"error": "unknown_device", "detail": messages.unknown_device(name)}
                )
            stored = store.device_by_id(device["device_id"])
            if stored is None:
                return Reply.json(
                    404, {"error": "unknown_device", "detail": messages.unknown_device(name)}
                )
            if stored["session_state"] in _STOPPING_STATES:
                return Reply.json(
                    409,
                    {
                        "error": "stopped_by_person",
                        "detail": "hands: this device session has stopped.",
                    },
                )
            if not stored["policy_ok"]:
                return Reply.json(
                    409, {"error": "policy_changed", "detail": messages.policy_changed(name)}
                )
            if not stored["online"]:
                return Reply.json(409, {"error": "offline", "detail": messages.offline(name)})
            if kind == "checkup" and "checkup-v1" not in stored["capabilities"]:
                return Reply.json(
                    409,
                    {
                        "error": "unsupported_capability",
                        "detail": "hands: this device does not advertise checkup-v1.",
                    },
                )
            self._jobs[job_id] = _Job(job_id, stored["device_id"], name, job_type=kind)
            self._queues.setdefault(stored["device_id"], deque()).append(payload)
            self._wake_locked(stored["device_id"])
        return Reply.json(200, {"job_id": job_id})

    async def local_output(self, principal, headers, path: str, body: bytes) -> Reply:
        refusal = self._local_refusal(principal, headers)
        if refusal is not None:
            return refusal
        try:
            request = json.loads(body)
            job_id, after = str(request["job_id"]), max(int(request.get("after", 0)), 0)
            wait = min(max(float(request.get("wait", MAX_OUTPUT_WAIT)), 0.0), MAX_OUTPUT_WAIT)
        except (ValueError, KeyError, TypeError, AttributeError):
            return Reply.json(400, {"error": "bad_request", "detail": messages.BAD_REQUEST})
        now = time.monotonic()
        deadline, next_check = now + wait, now
        while True:
            with self._lock:
                job = self._jobs.get(job_id)
                if job is None:
                    return Reply.json(404, {"error": "unknown_job", "detail": messages.RELAY_LOST})
                job.last_fetch = time.monotonic()
                if job.done or job.received > after or job.last_fetch >= deadline:
                    return Reply.json(200, self._take_locked(job, after))
                waiter = None if job.last_fetch >= next_check else self._waiter_locked(job_id)
            if waiter is None:
                await asyncio.to_thread(self._check_device, job)
                next_check = time.monotonic() + _LIVENESS_EVERY
                continue
            await self._wait(job_id, waiter, min(deadline, next_check) - time.monotonic())

    async def local_cancel(self, principal, headers, path: str, body: bytes) -> Reply:
        refusal = self._local_refusal(principal, headers)
        if refusal is not None:
            return refusal
        try:
            job_id = str(json.loads(body)["job_id"])
        except (ValueError, KeyError, TypeError):
            return Reply.json(400, {"error": "bad_request", "detail": messages.BAD_REQUEST})
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                self._cancel_locked(job)
        return Reply.json(200, {"ok": True})

    async def local_state(self, principal, headers, path: str, body: bytes) -> Reply:
        refusal = self._local_refusal(principal, headers)
        if refusal is not None:
            return refusal
        return Reply.json(200, await self.state())

    async def state(self) -> dict:
        """What ``/local/state`` and ``/ui/state`` show: the relay is up, every paired device, and an
        alert for each device refused for a changed deny-list."""
        devices = await asyncio.to_thread(store.list_devices)
        return {"relay": True, "devices": devices, "alerts": messages.alerts(devices)}


_relay: Relay | None = None
_relay_lock = threading.Lock()


def serve(keys: Keys | None, *, here: bool) -> Relay | Reply:
    """This process's relay, created and started on first use; a 503 :class:`Reply` when this process
    cannot be the relay (no seed yet, or it is the gateway, whose copy of the routes stays inert)."""
    global _relay
    if keys is None:
        return Reply.json(503, {"error": "not_set_up", "detail": messages.NOT_SET_UP})
    if not here:
        return Reply.json(503, {"error": "relay_elsewhere", "detail": messages.RELAY_ELSEWHERE})
    with _relay_lock:
        if _relay is None:
            _relay = Relay(keys)
            _relay.start()
        return _relay
