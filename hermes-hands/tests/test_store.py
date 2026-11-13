import sqlite3
import time

import pytest

from hands import protocol, store
from hands_fakes import hands_db  # noqa: F401  (fixture)


def _pair(name="laptop", policy_hash="p0"):
    code = store.mint_pairing_code(name)
    return store.complete_pairing(
        code,
        name=name,
        public_key=protocol.b64u(b"k" * 32),
        os="Linux",
        home="/home/r",
        policy_hash=policy_hash,
    )


def test_pairing_code_is_single_use(hands_db):
    code = store.mint_pairing_code("laptop")
    assert store.pairing_code_name(code) == "laptop"
    device_id = store.complete_pairing(
        code,
        name="laptop",
        public_key=protocol.b64u(b"k" * 32),
        os="Linux",
        home="/home/r",
        policy_hash="p0",
    )
    assert len(device_id) == 16
    assert store.pairing_code_name(code) is None
    with pytest.raises(store.PairingError) as burned:
        store.complete_pairing(
            code, name="laptop", public_key="x", os="Linux", home="/", policy_hash="p0"
        )
    assert (burned.value.status, burned.value.error) == (401, "bad_code")


def test_pairing_code_keeps_owner_label_until_successful_pair(hands_db):
    code = store.mint_pairing_code("laptop", owner_label="Ridwan")

    assert store.pairing_code_owner_label(code) == "Ridwan"
    device_id = store.complete_pairing(
        code,
        name="laptop",
        public_key=protocol.b64u(b"k" * 32),
        os="Windows",
        home="C:\\Users\\r",
        policy_hash="p0",
    )
    assert len(device_id) == 16
    assert store.pairing_code_owner_label(code) is None


def test_old_pairing_code_table_gains_owner_label_column(hands_db):
    conn = sqlite3.connect(hands_db / "hands.db")
    conn.execute(
        "CREATE TABLE pairing_codes (code_hash TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)"
    )
    conn.commit()
    conn.close()

    code = store.mint_pairing_code("laptop", owner_label="Ridwan")

    assert store.pairing_code_owner_label(code) == "Ridwan"


def test_expired_code_is_refused(hands_db):
    code = store.mint_pairing_code("laptop", ttl=-1)
    assert store.pairing_code_name(code) is None
    with pytest.raises(store.PairingError) as expired:
        store.complete_pairing(
            code, name="laptop", public_key="x", os="Linux", home="/", policy_hash="p0"
        )
    assert expired.value.status == 401


def test_name_rules(hands_db):
    _pair("laptop")
    with pytest.raises(store.PairingError) as taken:
        _pair("laptop")
    assert (taken.value.status, taken.value.error, taken.value.name) == (
        409,
        "name_taken",
        "laptop",
    )
    code = store.mint_pairing_code("desk")
    with pytest.raises(store.PairingError) as mismatch:
        store.complete_pairing(
            code, name="other", public_key="x", os="Linux", home="/", policy_hash="p0"
        )
    assert (mismatch.value.error, mismatch.value.name) == ("name_mismatch", "desk")
    assert store.pairing_code_name(code) == "desk"  # a refused pairing does not burn the code


def test_device_listing_and_revoke_frees_the_name(hands_db):
    device_id = _pair("laptop")
    [listed] = store.list_devices()
    assert listed == {**store.get_device("laptop")}
    assert set(listed) == {"device_id", "name", "os", "home", "last_seen", "online", "policy_ok"}
    assert listed["online"] and listed["policy_ok"] and listed["device_id"] == device_id
    assert store.device_by_id(device_id)["public_key"] == b"k" * 32
    assert store.revoked_key(device_id) is None
    assert store.revoke("laptop") is True
    assert store.revoke("laptop") is False
    assert store.get_device("laptop") is None and store.device_by_id(device_id) is None
    assert store.list_devices() == []
    assert store.revoked_key(device_id) == b"k" * 32  # the tombstone keeps the key
    again = _pair("laptop")
    assert [d["device_id"] for d in store.list_devices()] == [again]
    # R75: pairing the name again keeps the old key's tombstone, so the old laptop, offline when it
    # was revoked, still gets its signed stop when it wakes; the new device has its own id.
    assert store.revoked_key(again) is None and store.revoked_key(device_id) == b"k" * 32


def test_tombstones_last_a_grace_window_after_the_first_stop_or_their_ttl(hands_db, monkeypatch):
    """R65, R75: a device whose signed stop reply was lost asks again and is told again, until
    STOP_GRACE after the first stop; an untold tombstone lasts TOMBSTONE_TTL."""
    first, second = _pair("laptop"), _pair("desk")
    store.revoke("laptop")
    store.revoke("desk")
    now = time.time()
    store.mark_told(first)
    monkeypatch.setattr(time, "time", lambda: now + store.STOP_GRACE - 5)
    store.mark_told(first)  # a repeat stop does not move the window
    assert store.revoked_key(first) == b"k" * 32
    monkeypatch.setattr(time, "time", lambda: now + store.STOP_GRACE + 1)
    assert store.revoked_key(first) is None and store.revoked_key(second) == b"k" * 32
    later = now + store.TOMBSTONE_TTL + 1
    monkeypatch.setattr(time, "time", lambda: later)
    assert store.revoked_key(second) is None
    _pair("other")
    store.revoke("other")  # a revoke also clears expired tombstones from the table
    conn = sqlite3.connect(hands_db / "hands.db")
    rows = conn.execute("SELECT device_id FROM revoked_devices").fetchall()
    conn.close()
    assert second not in {row[0] for row in rows} and len(rows) == 1


def test_revoke_keeps_a_tombstone_in_a_hands_db_from_before_tombstones(hands_db):
    """An existing hands.db (no revoked_devices table) is migrated in place on first use."""
    conn = sqlite3.connect(hands_db / "hands.db")
    conn.execute(
        "CREATE TABLE devices (device_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,"
        " public_key TEXT NOT NULL, os TEXT NOT NULL, home TEXT NOT NULL,"
        " policy_hash TEXT NOT NULL, reported_policy_hash TEXT NOT NULL,"
        " policy_ok INTEGER NOT NULL DEFAULT 1, paired_at INTEGER NOT NULL,"
        " last_seen INTEGER NOT NULL)"
    )
    conn.execute(
        "INSERT INTO devices VALUES ('d1', 'laptop', ?, 'Linux', '/h', 'p0', 'p0', 1, 0, 0)",
        (protocol.b64u(b"k" * 32),),
    )
    conn.commit()
    conn.close()
    assert store.get_device("laptop")["device_id"] == "d1"
    assert store.revoke("laptop") is True
    assert store.revoked_key("d1") == b"k" * 32 and store.get_device("laptop") is None


def test_earlier_tombstone_and_target_tables_gain_their_columns_in_place(hands_db):
    conn = sqlite3.connect(hands_db / "hands.db")
    conn.execute(
        "CREATE TABLE revoked_devices (device_id TEXT PRIMARY KEY, public_key TEXT NOT NULL,"
        " revoked_at INTEGER NOT NULL, name TEXT NOT NULL DEFAULT '')"
    )
    conn.execute(
        "INSERT INTO revoked_devices VALUES ('old', ?, ?, 'laptop')",
        (protocol.b64u(b"k" * 32), int(time.time())),
    )
    conn.execute(
        "CREATE TABLE session_targets (session_key TEXT PRIMARY KEY, target TEXT NOT NULL)"
    )
    conn.execute("INSERT INTO session_targets VALUES ('s1', 'laptop')")
    conn.commit()
    conn.close()
    assert store.revoked_key("old") == b"k" * 32
    store.mark_told("old")
    assert store.revoked_key("old") == b"k" * 32
    assert store.get_session_target("s1") == ("laptop", "")  # bound to nobody: resolves to server
    store.set_session_target("s1", "laptop", owner="telegram:42")
    assert store.get_session_target("s1") == ("laptop", "telegram:42")


def test_no_device_can_be_paired_as_server(hands_db):
    code = store.mint_pairing_code(store.RESERVED_NAME)
    with pytest.raises(store.PairingError) as reserved:
        store.complete_pairing(
            code, name="server", public_key="AA", os="Linux", home="/", policy_hash="p0"
        )
    assert (reserved.value.status, reserved.value.error) == (409, "name_reserved")


def test_offline_after_last_seen(hands_db, monkeypatch):
    _pair("laptop")
    monkeypatch.setattr(store, "OFFLINE_AFTER", -1)
    assert store.get_device("laptop")["online"] is False


def test_policy_change_refuses_until_accepted(hands_db):
    device_id = _pair("laptop", policy_hash="p0")
    assert store.record_seen(device_id, policy_hash="p0", os="Windows", home="C:\\Users\\r") is True
    assert store.get_device("laptop")["os"] == "Windows"
    assert store.record_seen(device_id, policy_hash="p1") is False
    assert store.record_seen(device_id, policy_hash="p0") is False  # stays refused until accepted
    assert store.record_seen(device_id, policy_hash="p1") is False
    assert store.accept_policy("laptop") is True
    assert store.get_device("laptop")["policy_ok"] is True
    assert store.record_seen(device_id, policy_hash="p1") is True
    assert store.record_seen("nope") is None
    assert store.accept_policy("nope") is False


def test_session_targets(hands_db):
    assert store.get_session_target("s1") is None
    store.set_session_target("s1", "laptop", owner="telegram:42")
    store.set_session_target("s1", "server", owner="telegram:7")
    store.set_session_target("s2", "laptop")
    assert store.get_session_target("s1") == ("server", "telegram:7")
    assert store.get_session_target("s2") == ("laptop", "local")


def test_pairing_codes_are_matched_with_compare_digest(hands_db, monkeypatch):
    codes = [store.mint_pairing_code(name) for name in ("a", "b", "c")]
    calls = []
    real = store.hmac.compare_digest

    def spy(left, right):
        calls.append((left, right))
        return real(left, right)

    monkeypatch.setattr(store.hmac, "compare_digest", spy)
    assert store.pairing_code_name(codes[1]) == "b"
    assert len(calls) == 3  # every live candidate, not an SQL equality on the hash
    calls.clear()
    assert store.pairing_code_name("not-a-code") is None and len(calls) == 3
    calls.clear()
    store.complete_pairing(
        codes[2], name="c", public_key="AA", os="Linux", home="/", policy_hash="p"
    )
    assert len(calls) == 3
    assert store.pairing_code_name(codes[2]) is None and store.pairing_code_name(codes[0]) == "a"


def test_relay_heartbeat(hands_db, monkeypatch):
    assert store.relay_alive() is False
    store.write_relay_heartbeat()
    assert store.relay_alive() is True
    monkeypatch.setattr(time, "time", lambda: 10**10)
    assert store.relay_alive() is False
def test_old_device_table_gains_witness_state_columns_with_safe_defaults(hands_db):
    conn = sqlite3.connect(hands_db / "hands.db")
    conn.execute(
        "CREATE TABLE devices (device_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,"
        " public_key TEXT NOT NULL, os TEXT NOT NULL, home TEXT NOT NULL,"
        " policy_hash TEXT NOT NULL, reported_policy_hash TEXT NOT NULL,"
        " policy_ok INTEGER NOT NULL DEFAULT 1, paired_at INTEGER NOT NULL,"
        " last_seen INTEGER NOT NULL)"
    )
    conn.execute(
        "INSERT INTO devices VALUES ('d1', 'laptop', ?, 'Linux', '/home/r', 'p0', 'p0', 1, 1, 1)",
        (protocol.b64u(b"k" * 32),),
    )
    conn.commit()
    conn.close()

    device = store.device_by_id("d1")
    assert device["witness"] is False
    assert device["session_state"] == "normal"
    assert device["capabilities"] == []
    assert device["instance"] is None
    assert device["agent_version"] is None
    assert device["session_ended_at"] is None


def test_record_seen_persists_witness_state_and_stop_time(hands_db):
    device_id = _pair()
    assert (
        store.record_seen(
            device_id,
            policy_hash="p0",
            instance="instance-1",
            agent_version="0.2.0",
            witness=True,
            session_state="active",
            capabilities=["witness-v1", "checkup-v1"],
        )
        is True
    )
    active = store.device_by_id(device_id)
    assert active["witness"] is True
    assert active["session_state"] == "active"
    assert active["capabilities"] == ["witness-v1", "checkup-v1"]
    assert active["instance"] == "instance-1"
    assert active["agent_version"] == "0.2.0"
    assert active["session_ended_at"] is None

    assert (
        store.record_seen(
            device_id,
            policy_hash="p0",
            instance="instance-1",
            witness=True,
            session_state="stopping",
            capabilities=["witness-v1", "checkup-v1"],
        )
        is True
    )
    stopping = store.device_by_id(device_id)
    assert stopping["witness"] is False
    assert stopping["session_state"] == "stopping"
    assert stopping["capabilities"] == ["witness-v1", "checkup-v1"]
    assert isinstance(stopping["session_ended_at"], int)


def test_help_origin_and_outbox_retry_are_persistent_and_owner_scoped(hands_db, monkeypatch):
    device_id = _pair()
    origin = {
        "platform": "telegram",
        "chat_id": "chat-1",
        "chat_type": "dm",
        "user_id": "42",
    }
    store.record_seen(
        device_id,
        instance="serve-1",
        witness=True,
        session_state="active",
        capabilities=["witness-v1", "help-v1"],
    )
    store.set_help_origin(device_id, "telegram:42", origin, "session-1")
    assert store.get_help_origin(device_id) == {
        "owner": "telegram:42",
        "origin": origin,
        "session_key": "session-1",
    }

    assert (
        store.accept_help_request(
            device_id,
            request_id="a" * 32,
            instance="serve-1",
            text="please check this",
        )
        == "accepted"
    )
    assert (
        store.accept_help_request(
            device_id,
            request_id="a" * 32,
            instance="serve-1",
            text="changed duplicate text",
        )
        == "duplicate"
    )

    request = store.lease_help_request()
    assert request["request_id"] == "a" * 32
    assert request["text"] == "please check this"
    assert request["owner"] == "telegram:42"
    assert request["origin"] == origin
    assert request["session_key"] == "session-1"
    assert request["attempts"] == 1

    assert store.retry_help_request(request["request_id"], request["lease_token"])
    delayed = store.get_help_request(device_id, "a" * 32)
    assert delayed["status"] == "pending"
    assert 0 < delayed["next_attempt_at"] - time.time() <= store.HELP_RETRY_MAX_SECONDS
    monkeypatch.setattr(store.time, "time", lambda: delayed["next_attempt_at"] - 0.1)
    assert store.lease_help_request() is None
    monkeypatch.setattr(store.time, "time", lambda: delayed["next_attempt_at"] + 0.1)
    retried = store.lease_help_request()
    assert retried["attempts"] == 2
    assert store.mark_help_queued(retried["request_id"], retried["lease_token"])
    queued = store.get_help_request(device_id, "a" * 32)
    assert queued["status"] == "queued"
    assert queued["queued_at"] is not None


def test_help_requests_require_the_current_active_help_session(hands_db):
    device_id = _pair()
    origin = {
        "platform": "telegram",
        "chat_id": "chat-1",
        "chat_type": "dm",
        "user_id": "42",
    }
    store.set_help_origin(device_id, "telegram:42", origin, "session-1")
    assert (
        store.accept_help_request(
            device_id,
            request_id="b" * 32,
            instance="serve-1",
            text="help",
        )
        == "inactive"
    )
    store.record_seen(
        device_id,
        instance="serve-1",
        witness=True,
        session_state="active",
        capabilities=["witness-v1"],
    )
    assert (
        store.accept_help_request(
            device_id,
            request_id="c" * 32,
            instance="serve-1",
            text="help",
        )
        == "unsupported_capability"
    )
    store.record_seen(
        device_id,
        instance="serve-2",
        witness=True,
        session_state="active",
        capabilities=["witness-v1", "help-v1"],
    )
    assert (
        store.accept_help_request(
            device_id,
            request_id="d" * 32,
            instance="serve-1",
            text="help",
        )
        == "inactive"
    )
