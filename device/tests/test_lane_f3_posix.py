import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest


_CHILD = r"""
import importlib.util
import json
import os
import signal
import sys
import types
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])
if importlib.util.find_spec("httpx") is None:
    sys.modules["httpx"] = types.SimpleNamespace(HTTPError=type("HTTPError", (Exception,), {}))

from hermeshands_device import cli, config, janitor, loop
from hermeshands_device.protocol import b64u, generate_keypair

private, public = generate_keypair()
pairing = {"device_id": "test-device", "gateway_url": "https://example.test", "relay_public_key": b64u(public)}
original_loop = loop.DeviceLoop

def make_loop(**kwargs):
    agent = original_loop(**kwargs)
    agent._heartbeat_loop = lambda: None
    agent._help_loop = lambda: None

    def post(endpoint, body):
        assert endpoint == "/device/poll"
        print("F3_POLL_READY", flush=True)
        if sys.argv[2] == "noscreen":
            agent.stop_event.wait()
            return types.SimpleNamespace()
        signal.pause()
        raise AssertionError("poll resumed without shutdown")

    def heartbeat():
        if sys.argv[2] == "repeat":
            os.kill(os.getpid(), signal.SIGTERM)
        (config.ROOT / "final-heartbeat").write_text("mocked", encoding="utf-8")
        return True

    agent._post = post
    agent._verify_response = lambda *args: {}
    agent._send_final_heartbeat = heartbeat
    return agent

previous = signal.getsignal(signal.SIGTERM)
with patch.object(config, "load", return_value=pairing), \
     patch.object(loop, "get_or_create", return_value=(private, public)), \
     patch.object(loop.httpx, "Client", return_value=types.SimpleNamespace(), create=True), \
     patch.object(loop, "DeviceLoop", side_effect=make_loop), \
     patch.object(loop.screen, "unavailable", return_value=None if sys.argv[2] != "noscreen" else loop.screen.NOT_INSTALLED), \
     patch.object(janitor, "start"):
    code = cli.main(["serve", "--witness"])
    if sys.argv[2] == "noscreen":
        if code != 0:
            raise AssertionError("the stop key did not end the witness session")
    elif code != 130:
        raise AssertionError("SIGTERM did not interrupt the witness console")
    else:
        print("F3_INTERRUPT_HANDLED", flush=True)
assert signal.getsignal(signal.SIGTERM) == previous
print("F3_HANDLER_RESTORED", flush=True)
"""


@unittest.skipUnless(os.name == "posix", "requires a POSIX pseudo-terminal")
class SigtermTerminalTests(unittest.TestCase):
    def test_sigterm_restores_terminal_during_startup(self):
        self._terminate_at_prompt(started=False)

    def test_sigterm_flushes_receipt_and_restores_terminal_after_consent(self):
        self._terminate_at_prompt(started=True)

    def test_repeated_sigterm_does_not_interrupt_receipt_flush(self):
        self._terminate_at_prompt(started=True, repeat=True)

    def test_stop_key_ends_the_session_when_screenshots_are_unavailable(self):
        self._terminate_at_prompt(started=True, stop_key=True)

    def _terminate_at_prompt(self, *, started, repeat=False, stop_key=False):
        import pty
        import termios

        device = Path(__file__).resolve().parents[1]
        temporary_root = device.parent / ".pytest-tmp"
        temporary_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="f3-signal-", dir=temporary_root) as temporary:
            home = Path(temporary)
            environment = os.environ.copy()
            environment.update(HOME=str(home), TMPDIR=str(home), PYTHONDONTWRITEBYTECODE="1")
            environment.pop("HERMES_HANDS_JOB", None)
            master, slave = pty.openpty()
            previous = termios.tcgetattr(slave)
            output = bytearray()
            process = None

            def wait_for(predicate):
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if predicate():
                        return
                    if process.poll() is not None:
                        break
                    readable, _, _ = select.select([master], [], [], 0.02)
                    if readable:
                        output.extend(os.read(master, 65536))
                self.fail(f"child did not reach expected state: {output.decode(errors='replace')}")

            try:
                process = subprocess.Popen(
                    [sys.executable, "-c", _CHILD, str(device), "noscreen" if stop_key else "repeat" if repeat else "once"],
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    env=environment,
                )
                raw_flags = termios.ICANON | termios.ECHO | termios.ISIG
                wait_for(lambda: termios.tcgetattr(slave)[3] & raw_flags == 0)
                if started:
                    os.write(master, b"Y\n")
                    wait_for(lambda: b"F3_POLL_READY" in output)
                    wait_for(lambda: termios.tcgetattr(slave)[3] & raw_flags == 0)
                if stop_key:
                    wait_for(lambda: b"Type S and press Enter to stop" in output)
                    os.write(master, b"S\n")
                else:
                    process.send_signal(signal.SIGTERM)
                wait_for(lambda: b"F3_HANDLER_RESTORED" in output)
                self.assertEqual(process.wait(timeout=3), 0, output.decode(errors="replace"))
                if not stop_key:
                    self.assertIn(b"F3_INTERRUPT_HANDLED", output)
                # PENDIN is a kernel state bit (macOS sets it when canonical mode returns with input queued), not a setting.
                pending = getattr(termios, "PENDIN", 0)
                restored = termios.tcgetattr(slave)
                restored[3] &= ~pending
                previous[3] &= ~pending
                self.assertEqual(restored, previous)
                receipts = list((home / ".hermes-hands" / "receipts").glob("*.json"))
                if started:
                    self.assertEqual(len(receipts), 1)
                    payload = json.loads(receipts[0].read_text(encoding="utf-8-sig"))["payload"]
                    self.assertEqual(payload["end_reason"], "stopped_by_person")
                    self.assertEqual(payload["shutdown_delivery"], "confirmed")
                    self.assertEqual((home / ".hermes-hands" / "final-heartbeat").read_text(encoding="utf-8-sig"), "mocked")
                else:
                    self.assertEqual(receipts, [])
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                os.close(master)
                os.close(slave)
