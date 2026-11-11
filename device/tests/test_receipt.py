from datetime import datetime

import pytest

from hermeshands_device import checkup, receipt
from hermeshands_device.protocol import generate_keypair


def _payload():
    return {
        "schema_version": 1,
        "device_id": "device-1",
        "instance": "session-1",
        "started_at": "2026-11-08T10:00:00Z",
        "ended_at": "2026-11-08T10:05:00Z",
        "end_reason": "stopped_by_person",
        "shutdown_delivery": "confirmed",
        "events": [],
    }


def test_verification_rejects_receipt_signed_by_another_device(tmp_path, monkeypatch):
    monkeypatch.setattr(receipt.config, "ROOT", tmp_path)
    private, public = generate_keypair()
    _, local_public = generate_keypair()
    path, _ = receipt.write_receipt(_payload(), private, public)
    with pytest.raises(receipt.ReceiptError, match="different key"):
        receipt.verify_receipt(path, local_public)
    assert receipt.verify_receipt(path, public)["device_id"] == "device-1"


def test_receipts_sanitize_nested_values_and_bound_command_text(tmp_path, monkeypatch):
    monkeypatch.setattr(receipt.config, "ROOT", tmp_path)
    private, public = generate_keypair()
    payload = _payload()
    dirty = "before\x1b[1A\x1b[2K\u202e\x00\ud800after"
    payload["device_id"] = dirty
    payload["events"] = [{
        "timestamp": payload["started_at"],
        "label": "Running a command",
        "outcome": dirty + "x" * 3000,
        "checkup": {"facts": [{"label": dirty, "value": [dirty], "source": dirty}]},
    }]
    path, text_path = receipt.write_receipt(payload, private, public)
    saved = receipt.verify_receipt(path, public)
    assert saved["device_id"] == "beforeafter"
    assert len(saved["events"][0]["outcome"]) <= 2000
    assert saved["events"][0]["outcome"].endswith("...")
    assert saved["events"][0]["checkup"]["facts"][0]["value"] == ["beforeafter"]
    assert "\x1b" not in text_path.read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("reason, explanation", [
    ("stopped_by_person", "You stopped the session"),
    ("session_timeout", "The 30 minute limit ended the session"),
])
def test_text_receipt_uses_plain_words_and_local_time(tmp_path, monkeypatch, reason, explanation):
    monkeypatch.setattr(receipt.config, "ROOT", tmp_path)
    private, public = generate_keypair()
    payload = _payload()
    payload["end_reason"] = reason
    payload["events"] = [
        {"timestamp": payload["ended_at"], "label": "Session stopped", "outcome": f"Ended: {reason}", "delivery_status": "confirmed"},
        {"timestamp": payload["started_at"], "label": "Help request", "outcome": "Accepted by relay", "delivery_status": "accepted"},
        {"timestamp": payload["started_at"], "label": "Help request", "outcome": "Delivery not confirmed", "delivery_status": "pending"},
        {"timestamp": payload["started_at"], "label": "System checkup", "outcome": "Completed", "checkup": {"facts": [{"label": "Available memory", "source": "psutil.virtual_memory", "value": 42}]}},
    ]
    path, text_path = receipt.write_receipt(payload, private, public)
    text = text_path.read_text(encoding="utf-8-sig")
    assert explanation in text
    assert reason not in text
    assert "Final relay heartbeat" not in text
    assert "psutil" not in text
    assert "Help request: sent" in text
    assert "Help request: may not have reached your helper" in text
    assert "Help request: not sent" not in text
    assert datetime.fromisoformat(payload["started_at"].replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M") in text
    assert payload["started_at"] not in text
    assert receipt.verify_receipt(path, public)["shutdown_delivery"] == "confirmed"


def test_linux_pending_updates_does_not_claim_windows_checks(monkeypatch):
    monkeypatch.setattr(checkup.platform, "system", lambda: "Linux")
    fact = checkup._pending_updates_fact()
    assert "Windows" not in fact["label"]
    assert "Windows" not in fact["source"]
    assert fact["availability"] == "unsupported"


def test_text_receipt_translates_the_session_stopped_step(tmp_path, monkeypatch):
    monkeypatch.setattr(receipt.config, "ROOT", tmp_path)
    private, public = generate_keypair()
    payload = _payload()
    payload["events"] = [
        {"timestamp": payload["ended_at"], "label": "Session stopped", "outcome": "Ended: stopped_by_person", "delivery_status": "unconfirmed"},
        {"timestamp": payload["started_at"], "label": "Help request", "outcome": "Delivery not confirmed", "delivery_status": "pending"},
    ]
    _, text_path = receipt.write_receipt(payload, private, public)
    text = text_path.read_text(encoding="utf-8-sig")
    assert "Session stopped: You stopped the session" in text
    assert "Help request: may not have reached your helper" in text
    assert "Help request: not sent" not in text
    assert "unconfirmed" not in text


@pytest.mark.parametrize("reason, explanation", [
    ("revoked", "Your helper ended the pairing"),
    ("pairing_changed", "The pairing on this computer changed, so the session ended"),
    ("error", "An unexpected problem ended the session"),
])
def test_text_receipt_translates_abnormal_session_end_reasons(
    tmp_path, monkeypatch, reason, explanation
):
    monkeypatch.setattr(receipt.config, "ROOT", tmp_path)
    private, public = generate_keypair()
    payload = _payload()
    payload["end_reason"] = reason
    payload["events"] = [{
        "timestamp": payload["ended_at"],
        "label": "Session stopped",
        "outcome": f"Ended: {reason}",
        "delivery_status": "unconfirmed",
    }]
    path, text_path = receipt.write_receipt(payload, private, public)
    text = text_path.read_text(encoding="utf-8-sig")
    assert explanation in text.splitlines()
    assert f"Session stopped: {explanation}" in text
    assert reason not in text
    saved = receipt.verify_receipt(path, public)
    assert saved["schema_version"] == 1
    assert saved["end_reason"] == reason
    assert saved["events"][0]["outcome"] == f"Ended: {reason}"


@pytest.mark.parametrize("outcome, delivery_status, explanation", [
    ("Accepted by relay", "accepted", "sent"),
    ("Delivery not confirmed", "pending", "may not have reached your helper"),
    ("Not sent", "not_sent", "not sent"),
])
def test_text_receipt_reports_help_delivery_status(
    tmp_path, monkeypatch, outcome, delivery_status, explanation
):
    monkeypatch.setattr(receipt.config, "ROOT", tmp_path)
    private, public = generate_keypair()
    payload = _payload()
    payload["events"] = [{
        "timestamp": payload["started_at"],
        "label": "Help request",
        "outcome": outcome,
        "delivery_status": delivery_status,
    }]
    path, text_path = receipt.write_receipt(payload, private, public)
    text = text_path.read_text(encoding="utf-8-sig")
    assert text.splitlines()[-1].endswith(f"Help request: {explanation}")
    assert receipt.verify_receipt(path, public)["events"][0]["delivery_status"] == delivery_status


def test_key_mismatch_is_its_own_error(tmp_path, monkeypatch):
    monkeypatch.setattr(receipt.config, "ROOT", tmp_path)
    private, public = generate_keypair()
    _, other_public = generate_keypair()
    path, _ = receipt.write_receipt(_payload(), private, public)
    with pytest.raises(receipt.ReceiptKeyMismatch):
        receipt.verify_receipt(path, other_public)
