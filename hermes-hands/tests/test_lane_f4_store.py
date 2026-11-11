import pytest

from hands import store
from hands_fakes import Device, hands_db  # noqa: F401


@pytest.fixture
def help_request(hands_db, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(store.time, "time", lambda: now[0])
    device = Device()
    store.record_seen(
        device.device_id,
        instance="w1",
        witness=True,
        session_state="active",
        capabilities=["help-v1"],
    )
    store.set_help_origin(
        device.device_id, "telegram:42", {"platform": "telegram", "chat_id": "42"}, "s1"
    )
    assert store.accept_help_request(
        device.device_id, request_id="a" * 32, instance="w1", text="help"
    ) == "accepted"
    return device, now


@pytest.mark.parametrize("boundary", ["attempt_cap", "ttl", "retention"])
def test_help_pruning_preserves_live_delivery_lease(help_request, monkeypatch, boundary):
    device, now = help_request
    if boundary == "attempt_cap":
        for _ in range(store.HELP_MAX_ATTEMPTS - 1):
            request = store.lease_help_request()
            assert store.retry_help_request(request["request_id"], request["lease_token"])
            now[0] = store.get_help_request(device.device_id, "a" * 32)["next_attempt_at"]
    else:
        monkeypatch.setattr(store, "HELP_TTL_SECONDS", 10 if boundary == "ttl" else 100)
        monkeypatch.setattr(store, "HELP_RETENTION_SECONDS", 10)
        now[0] += 9

    request = store.lease_help_request()
    assert request is not None
    if boundary == "attempt_cap":
        assert request["attempts"] == store.HELP_MAX_ATTEMPTS
    if boundary == "retention":
        store.record_seen(device.device_id, witness=False, session_state="stopped")
    now[0] += 2
    assert now[0] < request["lease_until"]

    assert store.lease_help_request() is None
    current = store.get_help_request(device.device_id, request["request_id"])
    assert current is not None
    assert current["status"] == "leased"
    assert current["lease_token"] == request["lease_token"]
    assert store.mark_help_queued(request["request_id"], request["lease_token"])


def test_expired_final_help_lease_cannot_get_another_attempt(help_request):
    device, now = help_request
    for _ in range(store.HELP_MAX_ATTEMPTS - 1):
        request = store.lease_help_request()
        assert store.retry_help_request(request["request_id"], request["lease_token"])
        now[0] = store.get_help_request(device.device_id, "a" * 32)["next_attempt_at"]
    request = store.lease_help_request()
    assert request["attempts"] == store.HELP_MAX_ATTEMPTS
    now[0] = request["lease_until"]

    assert store.lease_help_request() is None
    assert store.get_help_request(device.device_id, request["request_id"])["status"] == "expired"
    assert not store.mark_help_queued(request["request_id"], request["lease_token"])
