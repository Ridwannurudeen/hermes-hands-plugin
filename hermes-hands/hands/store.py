"""Durable gateway state in SQLite under ``plugins.plugin_storage.plugin_db`` (public keys only, no secrets).

Shared by the gateway process (commands, tools, the terminal backend) and the dashboard process (the
relay); both must resolve the same ``HERMES_HOME``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

from . import protocol

PLUGIN = "hermes-hands"
OFFLINE_AFTER = (
    20  # seconds without a device request before it counts as offline; register() sets it
)
RELAY_STALE_AFTER = 15  # seconds; the relay writes its heartbeat row every 5
TOMBSTONE_TTL = 7 * 24 * 3600  # seconds a revoked device's key can still be told to stop
STOP_GRACE = 3600  # seconds the stop keeps being sent after the first one, in case it was lost
RESERVED_NAME = "server"  # the gateway host's own target name; no device may take it
HELP_RETRY_MAX_SECONDS = 60.0
HELP_MAX_ATTEMPTS = 5
HELP_TTL_SECONDS = 300
HELP_RETENTION_SECONDS = 86400
_HELP_LEASE_SECONDS = 30.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    os TEXT NOT NULL,
    home TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    reported_policy_hash TEXT NOT NULL,
    policy_ok INTEGER NOT NULL DEFAULT 1,
    paired_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    agent_version TEXT,
    instance TEXT,
    witness INTEGER NOT NULL DEFAULT 0,
    session_state TEXT NOT NULL DEFAULT 'normal',
    capabilities TEXT NOT NULL DEFAULT '[]',
    session_ended_at INTEGER
);
CREATE TABLE IF NOT EXISTS revoked_devices (
    device_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    revoked_at INTEGER NOT NULL,
    told_at INTEGER
);
CREATE TABLE IF NOT EXISTS pairing_codes (
    code_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_label TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS session_targets (
    session_key TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS device_help_origins (
    device_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    origin TEXT NOT NULL,
    session_key TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS help_requests (
    device_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    instance TEXT NOT NULL,
    text TEXT NOT NULL,
    owner TEXT NOT NULL,
    origin TEXT NOT NULL,
    session_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    lease_token TEXT,
    lease_until REAL,
    created_at REAL NOT NULL,
    queued_at REAL,
    PRIMARY KEY (device_id, request_id)
);
CREATE TABLE IF NOT EXISTS relay_heartbeat (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ts REAL NOT NULL
);
"""


class PairingError(Exception):
    """A pairing request the relay refuses; ``status`` and ``error`` go on the wire, ``name`` is the
    device name the refusal is about (the taken name, or the name the code was minted for)."""

    def __init__(self, status: int, error: str, name: str = ""):
        super().__init__(error)
        self.status = status
        self.error = error
        self.name = name


@contextmanager
def _db() -> Iterator[sqlite3.Connection]:
    """One connection per call, one transaction per ``with`` block (commit on success)."""
    from plugins.plugin_storage import plugin_db

    conn = plugin_db(PLUGIN, "hands.db")
    try:
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA)
        # In place for a hands.db from an earlier version (CREATE TABLE IF NOT EXISTS keeps its tables).
        _add_column(conn, "revoked_devices", "told_at", "INTEGER")
        _add_column(conn, "session_targets", "owner", "TEXT NOT NULL DEFAULT ''")
        _add_column(conn, "devices", "agent_version", "TEXT")
        _add_column(conn, "devices", "instance", "TEXT")
        _add_column(conn, "devices", "witness", "INTEGER NOT NULL DEFAULT 0")
        _add_column(conn, "devices", "session_state", "TEXT NOT NULL DEFAULT 'normal'")
        _add_column(conn, "devices", "capabilities", "TEXT NOT NULL DEFAULT '[]'")
        _add_column(conn, "devices", "session_ended_at", "INTEGER")
        _add_column(conn, "pairing_codes", "owner_label", "TEXT NOT NULL DEFAULT ''")
        with conn:
            yield conn
    finally:
        conn.close()


def _add_column(conn: sqlite3.Connection, table: str, column: str, kind: str) -> None:
    if column not in {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _public(row: sqlite3.Row, now: int) -> dict:
    return {
        "device_id": row["device_id"],
        "name": row["name"],
        "os": row["os"],
        "home": row["home"],
        "last_seen": row["last_seen"],
        "online": now - row["last_seen"] <= OFFLINE_AFTER,
        "policy_ok": bool(row["policy_ok"]),
    }


def mint_pairing_code(name: str, ttl: int = 600, *, owner_label: str = "") -> str:
    """A single-use code for one device; only its hash and consent-screen owner label are stored."""
    code = secrets.token_urlsafe(32)
    with _db() as conn:
        conn.execute(
            "INSERT INTO pairing_codes (code_hash, name, owner_label, expires_at) VALUES (?, ?, ?, ?)",
            (_code_hash(code), name, owner_label, int(time.time()) + ttl),
        )
    return code


def _live_code(conn: sqlite3.Connection, code: str, now: int) -> sqlite3.Row | None:
    """The live (unused, unexpired) row for ``code``. Every live digest is compared with
    ``hmac.compare_digest``, so the match is never decided by an SQL equality on the secret."""
    digest = _code_hash(code)
    match = None
    rows = conn.execute(
        "SELECT code_hash, name, owner_label FROM pairing_codes WHERE used = 0 AND expires_at > ?",
        (now,),
    ).fetchall()
    for row in rows:
        if hmac.compare_digest(row["code_hash"], digest):
            match = row
    return match


def pairing_code_name(code: str) -> str | None:
    """The device name a live pairing code was minted for, else None."""
    with _db() as conn:
        row = _live_code(conn, code, int(time.time()))
    return None if row is None else row["name"]


def pairing_code_owner_label(code: str) -> str | None:
    """The consent-screen owner label for a live code, else None for a legacy unlabeled code."""
    with _db() as conn:
        row = _live_code(conn, code, int(time.time()))
    return None if row is None or not row["owner_label"] else row["owner_label"]


def complete_pairing(
    code: str, *, name: str, public_key: str, os: str, home: str, policy_hash: str
) -> str:
    """Burn ``code`` and record the device in one transaction; returns the new device_id."""
    now = int(time.time())
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _live_code(conn, code, now)
        if row is None:
            raise PairingError(401, "bad_code")
        if row["name"] != name:
            raise PairingError(409, "name_mismatch", row["name"])
        if name == RESERVED_NAME:
            raise PairingError(409, "name_reserved", name)
        if conn.execute("SELECT 1 FROM devices WHERE name = ?", (name,)).fetchone() is not None:
            raise PairingError(409, "name_taken", name)
        device_id = secrets.token_hex(8)
        conn.execute("UPDATE pairing_codes SET used = 1 WHERE code_hash = ?", (row["code_hash"],))
        conn.execute(
            "INSERT INTO devices (device_id, name, public_key, os, home, policy_hash, reported_policy_hash,"
            " policy_ok, paired_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (device_id, name, public_key, os, home, policy_hash, policy_hash, now, now),
        )
    return device_id


def list_devices() -> list[dict]:
    now = int(time.time())
    with _db() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
    return [_public(row, now) for row in rows]


def get_device(name: str) -> dict | None:
    with _db() as conn:
        row = conn.execute("SELECT * FROM devices WHERE name = ?", (name,)).fetchone()
    return None if row is None else _public(row, int(time.time()))


def device_by_id(device_id: str) -> dict | None:
    """The full device record for the relay and the token provider, ``public_key`` as raw bytes."""
    with _db() as conn:
        row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if row is None:
        return None
    return {
        **_public(row, int(time.time())),
        "public_key": protocol.unb64u(row["public_key"]),
        "policy_hash": row["policy_hash"],
        "agent_version": row["agent_version"],
        "instance": row["instance"],
        "witness": bool(row["witness"]),
        "session_state": row["session_state"],
        "capabilities": json.loads(row["capabilities"]),
        "session_ended_at": row["session_ended_at"],
    }


def record_seen(
    device_id: str,
    *,
    policy_hash: str | None = None,
    os: str | None = None,
    home: str | None = None,
    agent_version: str | None = None,
    instance: str | None = None,
    witness: bool | None = None,
    session_state: str | None = None,
    capabilities: list[str] | None = None,
) -> bool | None:
    """Mark the device seen now with what it reported; a policy hash different from the accepted one
    turns ``policy_ok`` off until :func:`accept_policy`. Witness state and capabilities are committed
    with last-seen in the same transaction. Returns ``policy_ok``, or None if unknown."""
    capabilities_json = (
        None
        if capabilities is None
        else json.dumps(capabilities, ensure_ascii=False, separators=(",", ":"))
    )
    now = int(time.time())
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT instance, witness, session_state, capabilities, session_ended_at"
            " FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if current is None:
            return None

        next_witness = witness
        next_session_state = session_state
        next_capabilities = capabilities_json
        session_ended_at = current["session_ended_at"]
        new_instance = instance is not None and instance != current["instance"]
        same_instance = instance is None or instance == current["instance"]
        if session_state is not None:
            if current["session_state"] in ("stopping", "stopped") and session_state in (
                "normal",
                "active",
            ) and same_instance:
                next_witness = bool(current["witness"])
                next_session_state = current["session_state"]
                next_capabilities = current["capabilities"]
            else:
                if session_state in ("stopping", "stopped"):
                    next_witness = False
                    session_ended_at = session_ended_at or now
                elif session_state == "active" and new_instance:
                    session_ended_at = None

        conn.execute(
            "UPDATE devices SET last_seen = ?, os = COALESCE(?, os), home = COALESCE(?, home),"
            " reported_policy_hash = COALESCE(?, reported_policy_hash),"
            " policy_ok = CASE WHEN ? IS NOT NULL AND ? != policy_hash THEN 0 ELSE policy_ok END"
            ", agent_version = COALESCE(?, agent_version), instance = COALESCE(?, instance),"
            " witness = COALESCE(?, witness), session_state = COALESCE(?, session_state),"
            " capabilities = COALESCE(?, capabilities), session_ended_at = ? WHERE device_id = ?",
            (
                now,
                os,
                home,
                policy_hash,
                policy_hash,
                policy_hash,
                agent_version,
                instance,
                None if next_witness is None else int(next_witness),
                next_session_state,
                next_capabilities,
                session_ended_at,
                device_id,
            ),
        )
        row = conn.execute(
            "SELECT policy_ok FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
    return None if row is None else bool(row["policy_ok"])


def revoked_key(device_id: str) -> bytes | None:
    """The public key a revoked device signs with (its tombstone), else None. A tombstone lasts
    ``TOMBSTONE_TTL``, and ``STOP_GRACE`` after the first signed stop was sent: long enough for a
    device whose stop reply was lost to ask again, short enough that the old key soon stops being a
    token principal. Pairing the name again leaves it: the new device has a new device_id."""
    now = int(time.time())
    with _db() as conn:
        row = conn.execute(
            "SELECT public_key FROM revoked_devices WHERE device_id = ? AND revoked_at > ?"
            " AND (told_at IS NULL OR told_at > ?)",
            (device_id, now - TOMBSTONE_TTL, now - STOP_GRACE),
        ).fetchone()
    return None if row is None else protocol.unb64u(row["public_key"])


def mark_told(device_id: str) -> None:
    """Record when the device was first sent its signed ``unknown_device``."""
    with _db() as conn:
        conn.execute(
            "UPDATE revoked_devices SET told_at = COALESCE(told_at, ?) WHERE device_id = ?",
            (int(time.time()), device_id),
        )


def revoke(name: str) -> bool:
    """Delete the device, keeping its id and public key as a tombstone so the relay can answer its
    next request with a signed ``unknown_device``; the name is free to pair again."""
    now = int(time.time())
    with _db() as conn:
        conn.execute("DELETE FROM revoked_devices WHERE revoked_at <= ?", (now - TOMBSTONE_TTL,))
        conn.execute(
            "DELETE FROM help_requests WHERE device_id IN (SELECT device_id FROM devices WHERE name = ?)",
            (name,),
        )
        conn.execute(
            "DELETE FROM device_help_origins WHERE device_id IN (SELECT device_id FROM devices WHERE name = ?)",
            (name,),
        )
        conn.execute(
            "INSERT INTO revoked_devices (device_id, public_key, revoked_at)"
            " SELECT device_id, public_key, ? FROM devices WHERE name = ?",
            (now, name),
        )
        return conn.execute("DELETE FROM devices WHERE name = ?", (name,)).rowcount > 0


def accept_policy(name: str) -> bool:
    """Accept the deny-list hash the device last reported and let the relay serve it again."""
    with _db() as conn:
        return (
            conn.execute(
                "UPDATE devices SET policy_hash = reported_policy_hash, policy_ok = 1 WHERE name = ?",
                (name,),
            ).rowcount
            > 0
        )


def set_session_target(session_key: str, target: str, owner: str = "local") -> None:
    """Bind the session to ``target`` for ``owner`` (``targets.caller_id``), the person who chose it."""
    with _db() as conn:
        conn.execute(
            "INSERT INTO session_targets (session_key, target, owner) VALUES (?, ?, ?)"
            " ON CONFLICT(session_key) DO UPDATE SET target = excluded.target, owner = excluded.owner",
            (session_key, target, owner),
        )


def get_session_target(session_key: str) -> tuple[str, str] | None:
    """``(target, owner)`` for the session; a row from before owners were recorded has owner ``""``."""
    with _db() as conn:
        row = conn.execute(
            "SELECT target, owner FROM session_targets WHERE session_key = ?", (session_key,)
        ).fetchone()
    return None if row is None else (row["target"], row["owner"])


def set_help_origin(device_id: str, owner: str, origin: dict, session_key: str) -> bool:
    """Bind a selected device's help requests to the owner's validated chat origin."""
    encoded = json.dumps(origin, ensure_ascii=False, separators=(",", ":"))
    with _db() as conn:
        if conn.execute("SELECT 1 FROM devices WHERE device_id = ?", (device_id,)).fetchone() is None:
            return False
        conn.execute(
            "INSERT INTO device_help_origins (device_id, owner, origin, session_key, updated_at)"
            " VALUES (?, ?, ?, ?, ?) ON CONFLICT(device_id) DO UPDATE SET owner = excluded.owner,"
            " origin = excluded.origin, session_key = excluded.session_key, updated_at = excluded.updated_at",
            (device_id, owner, encoded, session_key, time.time()),
        )
    return True


def get_help_origin(device_id: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT owner, origin, session_key FROM device_help_origins WHERE device_id = ?",
            (device_id,),
        ).fetchone()
    if row is None:
        return None
    return {"owner": row["owner"], "origin": json.loads(row["origin"]), "session_key": row["session_key"]}


def accept_help_request(device_id: str, *, request_id: str, instance: str, text: str) -> str:
    """Persist one accepted help message with the device's selected owner origin."""
    now = time.time()
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        device = conn.execute(
            "SELECT witness, session_state, capabilities, instance FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if device is None:
            return "unknown_device"
        duplicate = conn.execute(
            "SELECT 1 FROM help_requests WHERE device_id = ? AND request_id = ?",
            (device_id, request_id),
        ).fetchone()
        if duplicate is not None:
            return "duplicate"
        if (
            not device["witness"]
            or device["session_state"] != "active"
            or device["instance"] != instance
        ):
            return "inactive"
        if "help-v1" not in json.loads(device["capabilities"]):
            return "unsupported_capability"
        origin = conn.execute(
            "SELECT owner, origin, session_key FROM device_help_origins WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if origin is None:
            return "owner_origin_required"
        count = conn.execute(
            "SELECT COUNT(*) FROM help_requests WHERE device_id = ? AND instance = ?",
            (device_id, instance),
        ).fetchone()[0]
        if count >= 3:
            return "rate_limited"
        conn.execute(
            "INSERT INTO help_requests"
            " (device_id, request_id, instance, text, owner, origin, session_key, next_attempt_at, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                device_id,
                request_id,
                instance,
                text,
                origin["owner"],
                origin["origin"],
                origin["session_key"],
                now,
                now,
            ),
        )
    return "accepted"


def get_help_request(device_id: str, request_id: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM help_requests WHERE device_id = ? AND request_id = ?",
            (device_id, request_id),
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["origin"] = json.loads(result["origin"])
    return result


def lease_help_request() -> dict | None:
    """Lease the next due request; an expired lease makes an interrupted delivery retryable."""
    now = time.time()
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        # Retain current-session rows for dedupe and the three-request quota, even
        # after delivery expires. Old sessions' rows have a bounded retention.
        conn.execute(
            "DELETE FROM help_requests WHERE created_at <= ?"
            " AND (status != 'leased' OR lease_until <= ?) AND NOT EXISTS"
            " (SELECT 1 FROM devices d WHERE d.device_id = help_requests.device_id"
            " AND d.instance = help_requests.instance AND d.witness = 1 AND d.session_state = 'active')",
            (now - HELP_RETENTION_SECONDS, now),
        )
        conn.execute(
            "UPDATE help_requests SET status = 'expired', lease_token = NULL, lease_until = NULL"
            " WHERE (status = 'pending' OR (status = 'leased' AND lease_until <= ?))"
            " AND (created_at <= ? OR attempts >= ?)",
            (now, now - HELP_TTL_SECONDS, HELP_MAX_ATTEMPTS),
        )
        row = conn.execute(
            "SELECT * FROM help_requests WHERE"
            " (status = 'pending' AND next_attempt_at <= ?)"
            " OR (status = 'leased' AND lease_until <= ?)"
            " ORDER BY created_at, request_id LIMIT 1",
            (now, now),
        ).fetchone()
        if row is None:
            return None
        token = secrets.token_hex(16)
        attempts = row["attempts"] + 1
        lease_until = now + _HELP_LEASE_SECONDS
        conn.execute(
            "UPDATE help_requests SET status = 'leased', attempts = ?, lease_token = ?, lease_until = ?"
            " WHERE device_id = ? AND request_id = ?",
            (attempts, token, lease_until, row["device_id"], row["request_id"]),
        )
        request = dict(row)
    request.update(
        status="leased", attempts=attempts, lease_token=token, lease_until=lease_until
    )
    request["origin"] = json.loads(request["origin"])
    return request


def mark_help_queued(request_id: str, lease_token: str) -> bool:
    """Record host acceptance of an injection; it does not claim that the message was delivered."""
    with _db() as conn:
        return (
            conn.execute(
                "UPDATE help_requests SET status = 'queued', queued_at = ?, lease_token = NULL,"
                " lease_until = NULL WHERE request_id = ? AND status = 'leased' AND lease_token = ?",
                (time.time(), request_id, lease_token),
            ).rowcount
            > 0
        )


def retry_help_request(request_id: str, lease_token: str) -> bool:
    """Return an unaccepted lease to pending with an exponential delay capped at one minute."""
    now = time.time()
    with _db() as conn:
        row = conn.execute(
            "SELECT attempts FROM help_requests WHERE request_id = ? AND status = 'leased'"
            " AND lease_token = ?",
            (request_id, lease_token),
        ).fetchone()
        if row is None:
            return False
        delay = min(2.0 ** max(row["attempts"] - 1, 0), HELP_RETRY_MAX_SECONDS)
        return (
            conn.execute(
                "UPDATE help_requests SET status = 'pending', next_attempt_at = ?,"
                " lease_token = NULL, lease_until = NULL WHERE request_id = ?"
                " AND status = 'leased' AND lease_token = ?",
                (now + delay, request_id, lease_token),
            ).rowcount
            > 0
        )


def release_help_request(request_id: str, lease_token: str) -> bool:
    """Return a lease the host refused to pending and give back its attempt, so a process that
    cannot deliver never spends one; the request still expires by age (``HELP_TTL_SECONDS``)."""
    with _db() as conn:
        return (
            conn.execute(
                "UPDATE help_requests SET status = 'pending', attempts = attempts - 1,"
                " lease_token = NULL, lease_until = NULL WHERE request_id = ?"
                " AND status = 'leased' AND lease_token = ?",
                (request_id, lease_token),
            ).rowcount
            > 0
        )


def write_relay_heartbeat() -> None:
    with _db() as conn:
        conn.execute(
            "INSERT INTO relay_heartbeat (id, ts) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET ts = excluded.ts",
            (time.time(),),
        )


def relay_alive() -> bool:
    """True when the relay wrote its heartbeat row in the last ``RELAY_STALE_AFTER`` seconds."""
    with _db() as conn:
        row = conn.execute("SELECT ts FROM relay_heartbeat WHERE id = 1").fetchone()
    return row is not None and time.time() - row["ts"] <= RELAY_STALE_AFTER
