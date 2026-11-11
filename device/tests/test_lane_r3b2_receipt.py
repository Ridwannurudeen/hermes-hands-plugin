import json
from pathlib import Path

import pytest

from hermeshands_device import cli, receipt
from hermeshands_device.protocol import b64u, generate_keypair


def _receipt_with_lone_surrogate(path):
    _, public = generate_keypair()
    payload = {
        "schema_version": 1,
        "public_key": b64u(public),
        "device_id": "device-1",
        "events": [],
    }
    text = json.dumps({"payload": payload, "signature": b64u(b"s" * 64)})
    path.write_text(text.replace('"device-1"', '"\\ud800"'), encoding="utf-8")
    return public


def test_receipt_with_a_lone_surrogate_fails_verification_cleanly(tmp_path):
    path = tmp_path / "receipt.json"
    public = _receipt_with_lone_surrogate(path)
    with pytest.raises(receipt.ReceiptError):
        receipt.verify_receipt(path, public)


def test_deeply_nested_receipt_fails_verification_cleanly(tmp_path):
    path = tmp_path / "receipt.json"
    path.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    _, public = generate_keypair()
    with pytest.raises(receipt.ReceiptError, match="could not read JSON receipt"):
        receipt.verify_receipt(path, public)


def test_cli_reports_a_crafted_receipt_without_a_traceback(tmp_path, capsys):
    path = tmp_path / "receipt.json"
    public = _receipt_with_lone_surrogate(path)
    assert cli.main(["receipt", "verify", str(path), f"--key={b64u(public)}"]) == 1
    assert capsys.readouterr().err.startswith("Receipt verification failed: ")


def test_device_test_sources_have_no_literal_bidi_controls():
    bidi = {chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}
    offenders = [
        path.name
        for path in Path(__file__).parent.glob("test_*.py")
        if bidi & set(path.read_text(encoding="utf-8-sig"))
    ]
    assert offenders == []
