import sys
import threading
import types

import pytest

from hermeshands_device import cli, config, receipt
from hermeshands_device.protocol import unb64u


DIRTY_TEXT = "before\x1b[1A\x1b[2K\u202e\x00after"


@pytest.fixture(autouse=True)
def isolated_device_paths(tmp_path, monkeypatch):
    monkeypatch.delenv("HERMES_HANDS_JOB", raising=False)
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(config, "POLICY_PATH", tmp_path / "policy.json")
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    monkeypatch.setattr(config, "OUT_DIR", tmp_path / "out")


@pytest.mark.parametrize("transport_error", [False, True])
def test_pairing_sanitizes_server_and_transport_errors(monkeypatch, capsys, transport_error):
    monkeypatch.setattr(cli, "get_or_create", lambda: (b"p" * 32, b"q" * 32))
    monkeypatch.setattr(cli.policy, "digest", lambda: "policy")

    def post(url, **kwargs):
        if transport_error:
            raise cli.httpx.ConnectError(DIRTY_TEXT)
        return cli.httpx.Response(400, text=DIRTY_TEXT)

    monkeypatch.setattr(cli.httpx, "post", post)
    assert cli._pair("https://gateway.example.test", "laptop", "code") == 1
    output = capsys.readouterr().err
    assert "beforeafter" in output
    assert "\x1b" not in output
    assert "\u202e" not in output
    assert "\x00" not in output


@pytest.mark.parametrize("version_result", ["success", "windowsapps", "stdout", "stderr"])
def test_doctor_sanitizes_dynamic_diagnostics(monkeypatch, capsys, version_result):
    monkeypatch.setattr(cli.executor, "resolve_bash", lambda: DIRTY_TEXT)
    monkeypatch.setattr(cli.shutil, "which", lambda name: DIRTY_TEXT)
    monkeypatch.setattr(config, "gateway_url", lambda: "https://gateway.example.test")
    monkeypatch.setitem(sys.modules, "keyring", types.SimpleNamespace(get_keyring=lambda: object()))

    def run(args, **kwargs):
        if "command -v" in args[-1]:
            prefix = "WindowsApps/" if version_result == "windowsapps" else "/bin/"
            return types.SimpleNamespace(returncode=0, stdout=prefix + DIRTY_TEXT)
        return types.SimpleNamespace(
            returncode=0 if version_result == "success" else 1,
            stdout="" if version_result == "stderr" else DIRTY_TEXT,
            stderr=DIRTY_TEXT,
        )

    def get(*args, **kwargs):
        raise cli.httpx.ConnectError(DIRTY_TEXT)

    monkeypatch.setattr(cli.subprocess, "run", run)
    monkeypatch.setattr(cli.httpx, "get", get)
    assert cli._doctor() == 1
    output = capsys.readouterr().out
    assert "bash: beforeafter" in output
    assert "git: beforeafter" in output
    assert "gateway: unreachable (beforeafter)" in output
    assert "\x1b" not in output
    assert "\u202e" not in output
    assert "\x00" not in output


def test_receipt_verification_sanitizes_dynamic_error(monkeypatch, tmp_path, capsys):
    def verify(*args):
        raise receipt.ReceiptError(DIRTY_TEXT)

    monkeypatch.setattr(receipt, "verify_receipt", verify)
    assert cli.main(["receipt", "verify", str(tmp_path / "receipt.json"), "--key=" + "A" * 43]) == 1
    assert capsys.readouterr().err == "Receipt verification failed: beforeafter\n"


def test_policy_show_sanitizes_user_controlled_patterns(monkeypatch, capsys):
    monkeypatch.setattr(cli.policy, "patterns", lambda: [DIRTY_TEXT])
    assert cli.main(["policy", "show"]) == 0
    assert capsys.readouterr().out == "beforeafter\n"


def test_argument_errors_sanitize_user_controlled_values(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["status", DIRTY_TEXT])
    assert exc.value.code == 2
    output = capsys.readouterr().err
    assert "unrecognized arguments: beforeafter" in output
    assert "\x1b" not in output
    assert "\u202e" not in output
    assert "\x00" not in output


def test_argument_errors_strip_newlines_and_tabs_from_argument_values(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["status", "before\nFAKE STATUS\tafter"])
    assert exc.value.code == 2
    output = capsys.readouterr().err
    assert output.endswith("error: unrecognized arguments: beforeFAKE STATUSafter\n")
    assert "\nFAKE STATUS" not in output


def test_receipt_key_hint_uses_equals_form(tmp_path, capsys):
    assert cli.main(["receipt", "verify", str(tmp_path / "receipt.json")]) == 1
    assert capsys.readouterr().err == (
        "This computer has no device key. Run this again with --key=<device public key>.\n"
    )


def test_receipt_key_help_documents_dash_leading_keys(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["receipt", "verify", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--key=<key>" in output
    assert "dash" in output


def test_receipt_verifies_with_a_dash_leading_public_key_using_equals(tmp_path, capsys):
    private = (33).to_bytes(32, "big")
    key = "-mLU3DYJV6Ej75jYvS8F5Zre6xyO33qzmpZHe4KZ0xg"
    payload = {
        "schema_version": 1,
        "device_id": "device-1",
        "instance": "session-1",
        "started_at": "2026-11-08T10:00:00Z",
        "ended_at": "2026-11-08T10:05:00Z",
        "end_reason": "stopped_by_person",
        "shutdown_delivery": "confirmed",
        "events": [],
    }
    json_path, _ = receipt.write_receipt(payload, private, unb64u(key))
    assert cli.main(["receipt", "verify", str(json_path), f"--key={key}"]) == 0
    assert capsys.readouterr().out == (
        "This receipt was signed by the key you gave and has not been changed.\n"
        f"Key: {key}\n"
    )


def test_receipt_dash_leading_key_requires_equals_form(tmp_path, capsys):
    key = "-mLU3DYJV6Ej75jYvS8F5Zre6xyO33qzmpZHe4KZ0xg"
    with pytest.raises(SystemExit) as exc:
        cli.main(["receipt", "verify", str(tmp_path / "receipt.json"), "--key", key])
    assert exc.value.code == 2
    assert "argument --key: expected one argument" in capsys.readouterr().err


@pytest.mark.parametrize("interrupted_at", ["consent", "run"])
def test_witness_closes_console_owner_when_interrupted(monkeypatch, interrupted_at):
    from hermeshands_device import janitor, loop

    closed = []

    def consent(prompt):
        if interrupted_at == "consent":
            raise KeyboardInterrupt
        return "Y"

    owner = types.SimpleNamespace(startup_consent=consent, close=lambda: closed.append(True))
    agent = types.SimpleNamespace(console_owner=owner, stop_event=threading.Event(), _stop_lock=threading.Lock())

    def run():
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "TerminalConsole", lambda: types.SimpleNamespace(write=lambda text: None))
    monkeypatch.setattr(cli.sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(cli.sys, "stdout", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(config, "load", lambda: {"device_id": "device-1", "gateway_url": "https://gateway.example.test"})
    monkeypatch.setattr(loop, "DeviceLoop", lambda **kwargs: agent)
    monkeypatch.setattr(janitor, "start", lambda **kwargs: None)
    monkeypatch.setattr(agent, "run_forever", run, raising=False)

    assert cli.main(["serve", "--witness"]) == 130
    assert closed == [True]
