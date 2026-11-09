import json
import logging
import re
import time
import types

import pytest

from hermeshands_device import cli, config, receipt
from hermeshands_device.protocol import R2D, b64u, canonical_json, generate_keypair, new_nonce, sign_request


def _signed_pair_response(data, *, signed_data=None):
    relay_private, relay_public = generate_keypair()
    relay_key = b64u(relay_public)
    signed_payload = {**(data if signed_data is None else signed_data), "relay_public_key": relay_key}
    body = canonical_json(signed_payload)
    response_body = canonical_json({**data, "relay_public_key": relay_key})
    ts, nonce = int(time.time()), new_nonce()
    path = "/api/plugins/hermes-hands/pair"
    signature = sign_request(relay_private, R2D, ts, nonce, "POST", path, body)
    return cli.httpx.Response(
        200,
        content=response_body,
        headers={
            "X-Hands-Ts": str(ts),
            "X-Hands-Nonce": nonce,
            "X-Hands-Signature": signature,
        },
        request=cli.httpx.Request("POST", "https://hands.example.com" + path),
    )


def test_config_round_trip_and_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    config.save({"gateway_url": "https://example.test/api/plugins/hermes-hands", "device_id": "device-1", "relay_public_key": b64u(b"k" * 32)})
    assert config.gateway_url() == "https://example.test/api/plugins/hermes-hands"
    assert config.device_id() == "device-1"
    assert config.relay_public_key() == b"k" * 32
    assert json.loads(config.CONFIG_PATH.read_text(encoding="utf-8-sig"))["device_id"] == "device-1"


def test_status_and_policy_cli(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(config, "POLICY_PATH", tmp_path / "policy.json")
    config.save({"gateway_url": "https://gateway.test/api/plugins/hermes-hands", "device_id": "device-1"})
    assert cli.main(["status"]) == 0
    assert "device-1" in capsys.readouterr().out
    assert cli.main(["policy", "reset"]) == 0
    assert cli.main(["policy", "show"]) == 0
    assert "sudo" in capsys.readouterr().out


def test_pair_accepts_base_and_plugin_prefix_urls(monkeypatch, capsys):
    requests = []
    monkeypatch.setattr(cli.config, "load", lambda: {})
    monkeypatch.setattr(cli, "get_or_create", lambda: (b"p" * 32, b"q" * 32))
    monkeypatch.setattr(cli.policy, "digest", lambda: "policy")
    monkeypatch.setattr(
        cli.httpx,
        "post",
        lambda url, **kwargs: requests.append(url)
        or types.SimpleNamespace(status_code=401, text='{"detail":"Unauthorized"}'),
    )

    for url in (
        "https://hands.example.com/",
        "https://hands.example.com/api/plugins/hermes-hands/",
    ):
        assert cli._pair(url, "laptop", "code") == 1

    assert requests == [
        "https://hands.example.com/api/plugins/hermes-hands/pair",
        "https://hands.example.com/api/plugins/hermes-hands/pair",
    ]
    assert "unknown, expired or already used" in capsys.readouterr().err


def test_pair_refuses_insecure_non_loopback_url(monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "load", lambda: {})
    monkeypatch.setattr(cli, "get_or_create", lambda: (_ for _ in ()).throw(AssertionError("must validate first")))
    assert cli._pair("http://hands.example.com", "laptop", "code") == 1
    assert "https" in capsys.readouterr().err
    for url in ("http://localhost:9119", "http://127.0.0.1:9119", "http://[::1]:9119"):
        monkeypatch.setattr(cli, "get_or_create", lambda: (b"p" * 32, b"q" * 32))
        monkeypatch.setattr(cli.httpx, "post", lambda *args, **kwargs: types.SimpleNamespace(status_code=500, text="error"))
        assert cli._pair(url, "laptop", "code") == 1


def test_pair_reports_httpx_transport_error(monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "load", lambda: {})
    monkeypatch.setattr(cli, "get_or_create", lambda: (b"p" * 32, b"q" * 32))
    monkeypatch.setattr(cli.policy, "digest", lambda: "policy")
    def fail(url, **kwargs):
        raise cli.httpx.ConnectError("connection refused", request=cli.httpx.Request("POST", url))
    monkeypatch.setattr(cli.httpx, "post", fail)
    assert cli._pair("https://hands.example.com", "laptop", "code") == 1
    error = capsys.readouterr().err
    assert "https://hands.example.com/api/plugins/hermes-hands/pair" in error
    assert "connection refused" in error


def test_pair_refuses_existing_pairing_without_force(monkeypatch, capsys):
    requests = []
    monkeypatch.setattr(cli.config, "load", lambda: {"device_id": "existing-device"})
    monkeypatch.setattr(cli, "get_or_create", lambda: (b"p" * 32, b"q" * 32))
    monkeypatch.setattr(cli.policy, "digest", lambda: "policy")
    monkeypatch.setattr(
        cli.httpx,
        "post",
        lambda url, **kwargs: requests.append(url)
        or types.SimpleNamespace(status_code=401, text="unauthorized"),
    )
    saved = []
    monkeypatch.setattr(cli.config, "save", lambda data: saved.append(data))

    assert cli._pair("https://hands.example.com", "laptop", "code") == 1

    assert requests == []
    assert saved == []
    assert "--force" in capsys.readouterr().err


def test_pair_force_flag_is_parsed_and_forwarded(monkeypatch):
    calls = []
    monkeypatch.setattr(
        cli,
        "_pair",
        lambda url, name, code, *, force=False: calls.append((url, name, code, force)) or 0,
    )

    assert cli.main(["pair", "https://hands.example.com", "--name", "laptop", "--code", "code", "--force"]) == 0
    assert calls == [("https://hands.example.com", "laptop", "code", True)]


@pytest.mark.parametrize("response_data", [
    {"device_id": "device-1", "owner_label": "Ridwan"},
    {"device_id": "device-1"},
])
def test_pair_persists_only_owner_label_from_signed_relay_response(monkeypatch, response_data):
    saved = []
    monkeypatch.setattr(cli.config, "load", lambda: {})
    monkeypatch.setattr(cli.config, "save", saved.append)
    monkeypatch.setattr(cli, "get_or_create", lambda: (b"p" * 32, b"q" * 32))
    monkeypatch.setattr(cli.policy, "digest", lambda: "policy")
    response = _signed_pair_response(response_data)
    monkeypatch.setattr(cli.httpx, "post", lambda *args, **kwargs: response)

    assert cli._pair("https://hands.example.com", "laptop", "code") == 0

    assert saved[0]["device_id"] == "device-1"
    if "owner_label" in response_data:
        assert saved[0]["owner_label"] == "Ridwan"
    else:
        assert "owner_label" not in saved[0]


def test_pair_rejects_owner_label_tampering_in_signed_response(monkeypatch, capsys):
    saved = []
    monkeypatch.setattr(cli.config, "load", lambda: {})
    monkeypatch.setattr(cli.config, "save", saved.append)
    monkeypatch.setattr(cli, "get_or_create", lambda: (b"p" * 32, b"q" * 32))
    monkeypatch.setattr(cli.policy, "digest", lambda: "policy")
    signed = {"device_id": "device-1", "owner_label": "Ridwan"}
    tampered = {"device_id": "device-1", "owner_label": "Mallory"}
    response = _signed_pair_response(tampered, signed_data=signed)
    monkeypatch.setattr(cli.httpx, "post", lambda *args, **kwargs: response)

    assert cli._pair("https://hands.example.com", "laptop", "code") == 1

    assert saved == []
    assert "invalid relay signature" in capsys.readouterr().err


def test_pair_refuses_from_device_job(monkeypatch, capsys):
    monkeypatch.setenv("HERMES_HANDS_JOB", "1")
    monkeypatch.setattr(cli.config, "load", lambda: (_ for _ in ()).throw(AssertionError("pairing must not be read")))

    assert cli.main(["pair", "https://hands.example.com", "--name", "laptop", "--code", "code", "--force"]) == 1

    assert "device job" in capsys.readouterr().err


def test_unpair_refuses_from_device_job(monkeypatch, capsys):
    saved = []
    removed = []
    monkeypatch.setenv("HERMES_HANDS_JOB", "1")
    monkeypatch.setattr(cli.config, "save", lambda data: saved.append(data))
    monkeypatch.setattr(cli, "remove_key", lambda: removed.append(True))

    assert cli.main(["unpair"]) == 1

    assert saved == []
    assert removed == []
    assert "device job" in capsys.readouterr().err


def test_policy_reset_cli_refuses_from_device_job(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HERMES_HANDS_JOB", "1")
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "POLICY_PATH", tmp_path / "policy.json")

    assert cli.main(["policy", "reset"]) == 1

    assert not (tmp_path / "policy.json").exists()
    assert "device job" in capsys.readouterr().err


def test_doctor_executes_python_probe_and_names_windowsapps(monkeypatch, capsys):
    monkeypatch.setattr(cli.executor, "resolve_bash", lambda: "bash.exe")
    monkeypatch.setattr(cli.shutil, "which", lambda name: "git.exe")
    monkeypatch.setattr(cli.config, "gateway_url", lambda: "")
    monkeypatch.setattr(cli.sys, "platform", "win32")
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if "command -v python3" in args[-1]:
            return types.SimpleNamespace(returncode=0, stdout="/c/Users/u/AppData/Local/Microsoft/WindowsApps/python3\n")
        return types.SimpleNamespace(returncode=49, stdout="Python was not found\n")
    monkeypatch.setattr(cli.subprocess, "run", run)
    assert cli._doctor() == 1
    output = capsys.readouterr().out
    assert "WindowsApps alias" in output
    assert any('python3 -c "import sys; print(sys.version)"' in call[-1] for call in calls)


def test_doctor_requires_working_python3_when_python_works(monkeypatch, capsys):
    monkeypatch.setattr(cli.executor, "resolve_bash", lambda: "bash.exe")
    monkeypatch.setattr(cli.shutil, "which", lambda name: "git.exe")
    monkeypatch.setattr(cli.config, "gateway_url", lambda: "")
    monkeypatch.setattr(cli.sys, "platform", "linux")

    def run(args, **kwargs):
        command = args[-1]
        if "command -v python3" in command:
            return types.SimpleNamespace(returncode=0, stdout="/usr/bin/python3\n")
        if "python3 -c" in command:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="python3 stub")
        if "command -v python" in command:
            return types.SimpleNamespace(returncode=0, stdout="/usr/bin/python\n")
        return types.SimpleNamespace(returncode=0, stdout="3.14\n")

    monkeypatch.setattr(cli.subprocess, "run", run)
    assert cli._doctor() == 1
    assert "/usr/bin/python" in capsys.readouterr().out


def test_doctor_reports_python_probe_timeout(monkeypatch, capsys):
    monkeypatch.setattr(cli.executor, "resolve_bash", lambda: "bash.exe")
    monkeypatch.setattr(cli.shutil, "which", lambda name: "git.exe")
    monkeypatch.setattr(cli.config, "gateway_url", lambda: "")

    def run(args, **kwargs):
        if "python3 -c" in args[-1]:
            raise cli.subprocess.TimeoutExpired(args, kwargs["timeout"])
        if "command -v python3" in args[-1]:
            return types.SimpleNamespace(returncode=0, stdout="/usr/bin/python3\n")
        return types.SimpleNamespace(returncode=1, stdout="")

    monkeypatch.setattr(cli.subprocess, "run", run)
    assert cli._doctor() == 1
    assert "timed out while starting" in capsys.readouterr().out


@pytest.mark.parametrize("timed_out_command", ("python3", "python"))
def test_doctor_reports_command_probe_timeout_and_continues(monkeypatch, capsys, timed_out_command):
    monkeypatch.setattr(cli.executor, "resolve_bash", lambda: "bash.exe")
    monkeypatch.setattr(cli.shutil, "which", lambda name: "git.exe")
    monkeypatch.setattr(cli.config, "gateway_url", lambda: "")
    calls = []

    def run(args, **kwargs):
        command = args[-1]
        calls.append(command)
        if command == f"command -v {timed_out_command}":
            raise cli.subprocess.TimeoutExpired(args, kwargs["timeout"])
        return types.SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", run)
    assert cli._doctor() == 1
    output = capsys.readouterr().out
    assert f"python in bash: command -v {timed_out_command} timed out" in output
    assert f"command -v {('python' if timed_out_command == 'python3' else 'python3')}" in calls
    assert "git: git.exe" in output
    assert "gateway: not paired" in output


class FakeConsole:
    def __init__(self, *lines):
        self.lines = iter(lines)
        self.outputs = []
        self.prompts = []

    def write(self, text):
        self.outputs.append(text)

    def read_line(self, prompt):
        self.prompts.append(prompt)
        return next(self.lines, None)


class FakeDeviceLoop:
    last = None

    def __init__(self, *, allow_screen=False, transport=None, console=None):
        self.allow_screen = allow_screen
        self.console = console
        self.run = False
        self.witness = False
        self.session_state = "normal"
        self.capabilities = []
        from hermeshands_device.console import ConsoleOwner

        self.console_owner = ConsoleOwner(console, on_stop=lambda: None, on_help=lambda text: None)
        type(self).last = self

    def run_forever(self):
        self.run = True
        self.console_owner.close()
        self.console_owner.join(1)


def _prepare_witness_cli(
    monkeypatch,
    console,
    *,
    executable=r"C:\Python\python.exe",
    input_tty=True,
    output_tty=True,
    owner_label=None,
):
    from hermeshands_device import janitor, loop

    monkeypatch.setattr(cli, "TerminalConsole", lambda: console, raising=False)
    monkeypatch.setattr(cli.sys, "executable", executable)
    monkeypatch.setattr(cli.sys, "stdin", types.SimpleNamespace(isatty=lambda: input_tty))
    monkeypatch.setattr(cli.sys, "stdout", types.SimpleNamespace(isatty=lambda: output_tty))
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "gateway_url", lambda: "https://hands.example.test/api/plugins/hermes-hands")
    pairing = {
        "device_id": "device-1",
        "gateway_url": "https://hands.example.test/api/plugins/hermes-hands",
    }
    if owner_label is not None:
        pairing["owner_label"] = owner_label
    monkeypatch.setattr(config, "load", lambda: pairing)
    monkeypatch.setattr(janitor, "start", lambda **_kwargs: None)
    monkeypatch.setattr(loop, "DeviceLoop", FakeDeviceLoop)
    FakeDeviceLoop.last = None


@pytest.mark.parametrize(("input_tty", "output_tty"), [(False, True), (True, False)])
def test_witness_requires_stdin_and_stdout_ttys(monkeypatch, capsys, input_tty, output_tty):
    console = FakeConsole("Y")
    _prepare_witness_cli(monkeypatch, console, input_tty=input_tty, output_tty=output_tty)

    assert cli.main(["serve", "--witness"]) == 1

    assert console.prompts == []
    assert "stdin and stdout TTYs" in capsys.readouterr().err


def test_witness_refuses_pythonw(monkeypatch, capsys):
    console = FakeConsole("Y")
    _prepare_witness_cli(monkeypatch, console, executable=str(cli.Path("Python") / "pythonw.exe"))

    assert cli.main(["serve", "--witness"]) == 1

    assert console.prompts == []
    assert "pythonw" in capsys.readouterr().err.lower()


def test_witness_refuses_service_mode(monkeypatch, capsys):
    console = FakeConsole("Y")
    _prepare_witness_cli(monkeypatch, console)

    assert cli.main(["serve", "--witness", "--service"]) == 1

    assert console.prompts == []
    assert "service" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("answer", ["Y", "y"])
def test_witness_y_starts_session_after_initial_consent(monkeypatch, answer):
    console = FakeConsole(answer)
    _prepare_witness_cli(monkeypatch, console)

    assert cli.main(["serve", "--witness"]) == 0

    agent = FakeDeviceLoop.last
    assert agent.run is True
    assert agent.console is console
    assert agent.allow_screen is False
    assert agent.witness is True
    assert agent.session_state == "active"
    assert agent.capabilities == ["witness-v1", "checkup-v1", "help-v1", "receipt-v1"]
    text = "".join(console.outputs)
    assert "device-1" in text
    assert "device-1's Hermes wants to help" in text
    assert "hands.example.test" in text
    assert "30 minutes" in text
    assert "No mouse or keyboard control" in text
    assert "Commands and outcomes are recorded" in text
    assert len(console.prompts) == 1
    assert re.match(r"^\[\d{4}-\d{2}-\d{2}T[^\]]+Z\] Start witness mode\? \[Y/N\]: $", console.prompts[0])


def test_witness_startup_suppresses_httpx_info_logs(monkeypatch, capsys):
    from hermeshands_device import janitor

    console = FakeConsole("Y")
    real_start = janitor.start
    _prepare_witness_cli(monkeypatch, console)
    monkeypatch.setattr(janitor, "start", real_start)
    monkeypatch.setattr(janitor, "cleanup", lambda: 0)

    root_logger = logging.getLogger()
    httpx_logger = logging.getLogger("httpx")
    httpcore_logger = logging.getLogger("httpcore")
    monkeypatch.setattr(root_logger, "handlers", [])
    monkeypatch.setattr(root_logger, "level", logging.WARNING)
    monkeypatch.setattr(httpx_logger, "level", logging.NOTSET)
    monkeypatch.setattr(httpcore_logger, "level", logging.NOTSET)

    class NoopThread:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            pass

    def start_without_sweeper_thread(**kwargs):
        with monkeypatch.context() as patch:
            patch.setattr(janitor.threading, "Thread", NoopThread)
            real_start(**kwargs)

    monkeypatch.setattr(janitor, "start", start_without_sweeper_thread)

    poll_count = 4

    def run_with_fake_polls(self):
        self.run = True
        for _ in range(poll_count):
            httpx_logger.info(
                'HTTP Request: POST http://127.0.0.1:9119/api/plugins/hermes-hands/device/poll "HTTP/1.1 204 No Content"'
            )
        self.console_owner.close()
        self.console_owner.join(1)

    monkeypatch.setattr(FakeDeviceLoop, "run_forever", run_with_fake_polls)

    assert cli.main(["serve", "--witness"]) == 0

    console_text = "".join(console.outputs + console.prompts) + capsys.readouterr().err
    assert "Start witness mode? [Y/N]:" in console_text
    assert "INFO:httpx:" not in console_text
    assert httpx_logger.getEffectiveLevel() == logging.WARNING
    assert httpcore_logger.getEffectiveLevel() == logging.WARNING


def test_witness_consent_screen_uses_persisted_owner_label(monkeypatch):
    console = FakeConsole("Y")
    _prepare_witness_cli(monkeypatch, console, owner_label="Ridwan")

    assert cli.main(["serve", "--witness"]) == 0

    assert "Ridwan's Hermes wants to help" in "".join(console.outputs)


@pytest.mark.parametrize(("answer", "expected"), [("N", 0), ("n", 0), ("yes", 0), ("ok", 0), ("", 0), (None, 1)])
def test_witness_decline_or_eof_does_not_start_agent(monkeypatch, capsys, answer, expected):
    console = FakeConsole(answer)
    _prepare_witness_cli(monkeypatch, console)

    assert cli.main(["serve", "--witness"]) == expected

    assert FakeDeviceLoop.last is not None
    assert FakeDeviceLoop.last.run is False
    assert FakeDeviceLoop.last.witness is False
    assert "declined" in "".join(console.outputs).lower()
    assert len(console.prompts) == 1
    assert re.match(r"^\[\d{4}-\d{2}-\d{2}T[^\]]+Z\] Start witness mode\? \[Y/N\]: $", console.prompts[0])


@pytest.mark.parametrize("stop_answer", ["S", "s"])
def test_witness_stop_at_startup_consent_does_not_start_agent(monkeypatch, stop_answer):
    console = FakeConsole(stop_answer)
    _prepare_witness_cli(monkeypatch, console)

    assert cli.main(["serve", "--witness"]) == 0

    assert FakeDeviceLoop.last.run is False
    assert FakeDeviceLoop.last.witness is False


@pytest.mark.parametrize("with_bom", [False, True])
def test_receipt_files_are_signed_redacted_and_verifiable_from_cli(tmp_path, monkeypatch, capsys, with_bom):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    private, public = generate_keypair()
    payload = {
        "schema_version": 1,
        "device_id": "device-1",
        "instance": "0123456789abcdef",
        "started_at": "2026-11-08T10:00:00Z",
        "ended_at": "2026-11-08T10:05:00Z",
        "end_reason": "stopped_by_person",
        "shutdown_delivery": "pending",
        "events": [
            {
                "timestamp": "2026-11-08T10:01:00Z",
                "label": "Running a command",
                "outcome": "Completed with exit code 0",
                "script": "echo private-command",
                "output": "private-output",
            },
            {
                "timestamp": "2026-11-08T10:02:00Z",
                "label": "Help request",
                "outcome": "Accepted by relay",
                "delivery_status": "pending",
                "request_id": "a" * 32,
            },
            {
                "timestamp": "2026-11-08T10:03:00Z",
                "label": "System checkup",
                "outcome": "Completed",
                "checkup": {
                    "facts": [
                        {
                            "id": "memory.available",
                            "label": "Available memory",
                            "value": 4096,
                            "unit": "MiB",
                            "status": "ok",
                            "availability": "observed",
                            "source": "psutil.virtual_memory",
                        }
                    ]
                },
            },
        ],
    }

    json_path, text_path = receipt.write_receipt(payload, private, public)
    if with_bom:
        json_path.write_bytes(b"\xef\xbb\xbf" + json_path.read_bytes())

    assert json_path.suffix == ".json"
    assert text_path.suffix == ".txt"
    assert json_path.stem == text_path.stem
    envelope = json.loads(json_path.read_text(encoding="utf-8-sig"))
    assert set(envelope) == {"payload", "signature"}
    assert "signature" not in envelope["payload"]
    assert receipt.verify_receipt(json_path) == envelope["payload"]
    assert envelope["payload"]["events"][0] == {
        "timestamp": "2026-11-08T10:01:00Z",
        "label": "Running a command",
        "outcome": "Completed with exit code 0",
    }
    text_receipt = text_path.read_text(encoding="utf-8-sig")
    assert "stopped_by_person" in text_receipt
    assert "Running a command: Completed with exit code 0" in text_receipt
    assert "Help request: Accepted by relay (delivery: pending)" in text_receipt
    assert "Available memory" in text_receipt
    assert "private-command" not in text_receipt
    assert "private-output" not in text_receipt
    assert "private-command" not in json_path.read_text(encoding="utf-8-sig")
    assert "private-output" not in json_path.read_text(encoding="utf-8-sig")

    assert cli.main(["receipt", "verify", str(json_path)]) == 0
    assert "signature verified" in capsys.readouterr().out.lower()

    envelope["payload"]["end_reason"] = "fabricated"
    json_path.write_text(json.dumps(envelope), encoding="utf-8")
    assert cli.main(["receipt", "verify", str(json_path)]) == 1
    assert "verification failed" in capsys.readouterr().err.lower()
