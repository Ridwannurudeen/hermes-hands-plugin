import sqlite3

import pytest

from hands import relay, store
from hands_fakes import Device, hands_db  # noqa: F401
from test_relay import body, device_call, hub, local, post_result, witness_fields  # noqa: F401


def _job(hub, **extra):
    return body(local(hub, "local_exec", {"device": "laptop", "script": "echo hi", "timeout": 30, **extra}))["job_id"]


@pytest.mark.parametrize("route,handler", [("/device/poll", "device_poll"), ("/device/heartbeat", "device_heartbeat")])
def test_queued_normal_job_does_not_enter_new_witness(hub, route, handler):
    device = Device()
    job_id = _job(hub)
    fields = {"instance": "new-witness", **witness_fields()}
    if handler == "device_poll":
        fields["wait"] = 0
    else:
        fields.update(policy_hash="p0", os="Windows", home="/home/r", agent_version="0.2.0")
    reply, _, _ = device_call(hub, device, handler, route, fields)
    assert reply.status in (200, 204)
    assert hub._jobs[job_id].done
    assert not hub._jobs[job_id].picked
    assert not hub._queues.get(device.device_id)


def test_queued_witness_job_does_not_enter_another_instance(hub):
    device = Device()
    device_call(hub, device, "device_poll", "/device/poll", {"wait": 0, "instance": "first", **witness_fields()})
    job_id = _job(hub, decision={"device_id": device.device_id, "state": [True, "active", "first"]})
    reply, _, _ = device_call(hub, device, "device_poll", "/device/poll", {"wait": 0, "instance": "second", **witness_fields()})
    assert reply.status == 204
    assert hub._jobs[job_id].done


@pytest.mark.parametrize("failure", [sqlite3.OperationalError("locked"), RuntimeError("broken")])
def test_beat_survives_reap_and_store_failures(hub, monkeypatch, caplog, failure):
    beats = []
    monkeypatch.setattr(store, "write_relay_heartbeat", lambda: beats.append(True))
    def broken():
        raise failure
    monkeypatch.setattr(hub, "_reap", broken)
    hub._beat()
    hub._beat()
    assert len(beats) == 2
    assert "reap" in caplog.text
    monkeypatch.setattr(store, "write_relay_heartbeat", broken)
    hub._beat()
    assert "heartbeat" in caplog.text


def test_help_text_strips_bidi_zero_width_and_surrogates():
    assert relay._help_text("help\u202e\u200b\ud800\x00 me") == "help me"


def test_heartbeat_strips_device_label_controls(hub):
    device = Device()
    reply, _, _ = device_call(hub, device, "device_heartbeat", "/device/heartbeat", {
        "policy_hash": "p0", "os": "Win\u202edows", "home": "/home/\u200br", "agent_version": "0.2.0\u200b",
    })
    assert reply.status == 200
    saved = store.device_by_id(device.device_id)
    assert (saved["os"], saved["home"], saved["agent_version"]) == ("Windows", "/home/r", "0.2.0")


def test_out_of_order_result_buffer_is_bounded(hub, monkeypatch):
    device = Device()
    job_id = _job(hub)
    monkeypatch.setattr(relay, "MAX_PENDING_CHUNKS", 2, raising=False)
    assert post_result(hub, device, job_id, 1, "a")[0].status == 200
    assert post_result(hub, device, job_id, 2, "b")[0].status == 200
    assert post_result(hub, device, job_id, 3, "c")[0].status == 413
    assert hub._jobs[job_id].done
    assert len(hub._jobs[job_id].chunks) <= 2


def _help(device):
    store.record_seen(device.device_id, witness=True, session_state="active", instance="w1", capabilities=["help-v1"])
    store.set_help_origin(device.device_id, "telegram:42", {"platform": "telegram", "chat_id": "42"}, "s1")
    assert store.accept_help_request(device.device_id, request_id="a" * 32, instance="w1", text="help") == "accepted"


def test_help_delivery_attempts_are_bounded(hands_db, monkeypatch):
    device = Device()
    _help(device)
    for attempt in range(5):
        request = store.lease_help_request()
        assert request is not None
        assert store.retry_help_request(request["request_id"], request["lease_token"])
        delayed = store.get_help_request(device.device_id, "a" * 32)
        monkeypatch.setattr(store.time, "time", lambda due=delayed["next_attempt_at"]: due + 1)
    assert store.lease_help_request() is None


def test_help_ttl_expires_delivery_but_preserves_current_session_quota(hands_db, monkeypatch):
    device = Device()
    _help(device)
    created = store.get_help_request(device.device_id, "a" * 32)["created_at"]
    monkeypatch.setattr(store.time, "time", lambda: created + 301)
    assert store.lease_help_request() is None
    assert store.accept_help_request(device.device_id, request_id="a" * 32, instance="w1", text="again") == "duplicate"
    monkeypatch.setattr(store.time, "time", lambda: created + 86401)
    assert store.lease_help_request() is None
    assert store.get_help_request(device.device_id, "a" * 32) is not None
    store.record_seen(device.device_id, witness=False, session_state="stopped", instance="w1")
    store.lease_help_request()
    assert store.get_help_request(device.device_id, "a" * 32) is None


def test_in_order_output_is_not_limited_by_the_out_of_order_cap(hub, monkeypatch):
    device = Device()
    job_id = _job(hub)
    monkeypatch.setattr(relay, "MAX_BUFFERED_CHARS", 4)
    for seq in range(3):
        assert post_result(hub, device, job_id, seq, "abcdefgh")[0].status == 200
    assert not hub._jobs[job_id].done
    assert hub._jobs[job_id].received == 3


def test_the_chunk_that_fills_a_gap_is_not_limited_by_the_out_of_order_cap(hub, monkeypatch):
    device = Device()
    job_id = _job(hub)
    monkeypatch.setattr(relay, "MAX_PENDING_CHUNKS", 2)
    assert post_result(hub, device, job_id, 1, "b")[0].status == 200
    assert post_result(hub, device, job_id, 2, "c")[0].status == 200
    assert post_result(hub, device, job_id, 0, "a")[0].status == 200
    assert not hub._jobs[job_id].done
    assert hub._jobs[job_id].received == 3


def test_out_of_order_characters_are_bounded(hub, monkeypatch):
    device = Device()
    job_id = _job(hub)
    monkeypatch.setattr(relay, "MAX_BUFFERED_CHARS", 4)
    assert post_result(hub, device, job_id, 1, "abc")[0].status == 200
    assert post_result(hub, device, job_id, 2, "de")[0].status == 413
    assert hub._jobs[job_id].done


def test_legacy_normal_device_reporting_its_instance_late_still_gets_the_job(hub):
    device = Device()
    job_id = _job(hub)
    reply, _, _ = device_call(hub, device, "device_poll", "/device/poll", {"wait": 0, "instance": "late"})
    assert reply.status == 200
    assert hub._jobs[job_id].picked
    assert not hub._jobs[job_id].done


def test_exec_poll_and_cancel_read_the_store_off_the_event_loop(hub, monkeypatch):
    import asyncio

    on_loop = []

    def watch(read):
        def wrapped(*args, **kwargs):
            try:
                asyncio.get_running_loop()
                on_loop.append(read.__name__)
            except RuntimeError:
                pass
            return read(*args, **kwargs)
        return wrapped

    device = Device()
    device_call(hub, device, "device_poll", "/device/poll", {"wait": 0})
    for name in ("get_device", "device_by_id"):
        monkeypatch.setattr(store, name, watch(getattr(store, name)))
    job_id = _job(hub)
    device_call(hub, device, "device_poll", "/device/poll", {"wait": 0})
    local(hub, "local_cancel", {"job_id": job_id})
    assert hub._jobs[job_id].done
    picked = _job(hub)
    for _ in range(2):  # the first poll hands out the cancel
        device_call(hub, device, "device_poll", "/device/poll", {"wait": 0})
    assert hub._jobs[picked].picked
    reply, _, _ = device_call(hub, device, "device_heartbeat", "/device/heartbeat", {
        "policy_hash": "edited", "os": "Windows", "home": "/home/r", "agent_version": "0.2.0",
    })
    assert reply.status == 409
    assert hub._jobs[picked].done
    assert on_loop == []
