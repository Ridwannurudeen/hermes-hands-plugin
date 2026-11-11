import time

import pytest

from hands import messages, relay
from hands_fakes import Device, hands_db  # noqa: F401  (fixture)
from test_relay import PEER, body, device_call, hub, local, run, witness_fields  # noqa: F401


def _active_witness_with_a_queued_job(hub):
    device = Device()
    active = {"wait": 0, "policy_hash": "p0", "instance": "instance-1", **witness_fields()}
    device_call(hub, device, "device_poll", "/device/poll", active)
    job_id = body(
        local(
            hub,
            "local_exec",
            {
                "device": "laptop",
                "script": "echo queued",
                "timeout": 5,
                "decision": {
                    "device_id": device.device_id,
                    "state": [True, "active", "instance-1"],
                },
            },
        )
    )["job_id"]
    return device, job_id


def _stopping(device, hub, **reason):
    heartbeat = {
        "policy_hash": "p0",
        "os": "Linux",
        "home": "/home/r",
        "agent_version": "0.2.0",
        "instance": "instance-1",
        **witness_fields(session_state="stopping"),
        **reason,
    }
    reply, _, _ = device_call(hub, device, "device_heartbeat", "/device/heartbeat", heartbeat)
    assert reply.status == 200, reply.body


@pytest.mark.parametrize(
    ("reason", "error", "returncode"),
    [
        ({}, "session_ended", 130),
        ({"stop_reason": "stopped_by_person"}, "stopped_by_person", 130),
        ({"stop_reason": "session_timeout"}, "session_timeout", 124),
    ],
    ids=["no_reason", "person", "timeout"],
)
def test_a_stop_without_a_reason_is_never_reported_as_the_person_stopping(
    hub, reason, error, returncode
):
    """r3-relay-skill-1: the device sends no stop_reason when it ends because of an error, so the
    relay must not tell the helper that the person stopped the session."""
    device, job_id = _active_witness_with_a_queued_job(hub)
    _stopping(device, hub, **reason)
    output = body(local(hub, "local_output", {"job_id": job_id, "after": 0, "wait": 0}))
    assert (output["done"], output["returncode"], output["error"]) == (True, returncode, error)
    refused = local(hub, "local_exec", {"device": "laptop", "script": "echo after", "timeout": 5})
    assert (refused.status, body(refused)["error"]) == (409, error)
    told = messages.device_result_error(output["error"], "laptop")
    assert ("stopped the session" in told) == (error == "stopped_by_person")


def test_the_nonce_is_burned_only_while_its_bearer_is_still_fresh(hub, monkeypatch):
    """r3-relay-skill-3: the token seam checks freshness at one second and the relay burns the nonce
    at a later one. A request that went stale in between must be refused, not accepted."""
    device = Device()
    principal, headers, path, raw = device.request("/device/poll", {"wait": 0})
    signed_at = int(time.time())
    monkeypatch.setattr(relay.time, "time", lambda: signed_at + 301.0)
    stale = run(hub.device_poll(principal, headers, path, raw, PEER))
    assert (stale.status, body(stale)["error"]) == (401, "stale")
    assert "X-Hands-Signature" not in stale.headers


def test_a_replay_at_the_edge_of_freshness_is_still_refused(hub, monkeypatch):
    device = Device()
    principal, headers, path, raw = device.request("/device/poll", {"wait": 0})
    signed_at = int(time.time())
    assert run(hub.device_poll(principal, headers, path, raw, PEER)).status == 204
    monkeypatch.setattr(relay.time, "time", lambda: signed_at + 300.0)
    replay = run(hub.device_poll(principal, headers, path, raw, PEER))
    assert (replay.status, body(replay)["error"]) == (401, "replayed")
