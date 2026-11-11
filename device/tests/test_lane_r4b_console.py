import sys
import threading
import types

import pytest

from hermeshands_device import console as console_module
from hermeshands_device.console import ConsoleOwner


class _Keys:
    """Keys arrive in bursts: the bytes of one burst are readable together, and the next burst comes later."""

    def __init__(self, *bursts):
        self.bursts = [list(burst) for burst in bursts]

    def _current(self):
        while self.bursts and not self.bursts[0]:
            self.bursts.pop(0)
        return self.bursts[0] if self.bursts else None

    def read(self, count):
        burst = self._current()
        return burst.pop(0) if burst else ""

    def os_read(self, descriptor, count):
        return self.read(count).encode("utf-8")

    def select(self, readers, writers, errors, timeout=None):
        ready = bool(self.bursts and self.bursts[0])
        return (readers if ready else []), [], []


def _posix_terminal(monkeypatch, keys):
    termios = types.ModuleType("termios")
    termios.TCSANOW = 1
    termios.ICANON = 2
    termios.ECHO = 4
    termios.ISIG = 8
    termios.error = OSError
    termios.tcgetattr = lambda descriptor: [0, 0, 0, 31, 0, 0, []]
    termios.tcsetattr = lambda descriptor, when, state: None
    output = []
    monkeypatch.setattr(console_module.os, "name", "posix")
    monkeypatch.setattr(console_module.os, "read", keys.os_read)
    monkeypatch.setattr(console_module, "select", types.SimpleNamespace(select=keys.select), raising=False)
    monkeypatch.setattr(console_module.sys, "stdin", types.SimpleNamespace(fileno=lambda: 7, read=keys.read, encoding="utf-8"))
    monkeypatch.setattr(console_module.sys, "stdout", types.SimpleNamespace(write=output.append, flush=lambda: None))
    monkeypatch.setitem(sys.modules, "termios", termios)
    return console_module.TerminalConsole(), output


def test_posix_arrow_keys_are_ignored_and_a_lone_escape_is_returned(monkeypatch):
    keys = _Keys("\x1b[A", "S\n", "\x1bOA", "\x1b[1;5C", "h\n", "\x1b")
    terminal, _ = _posix_terminal(monkeypatch, keys)
    assert [terminal.read_line("Prompt: ") for _ in range(3)] == ["S", "h", "\x1b"]


@pytest.mark.parametrize(
    ("bursts", "helped", "cancelled"),
    [
        (("H\n", "my printer is brok", "\x1b[D", "en\n", "S\n"), ["my printer is broken"], False),
        (("H\n", "abc", "\x1bOD", "d\n", "S\n"), ["abcd"], False),
        (("H\n", "abc", "\x1b", "S\n"), [], True),
    ],
)
def test_arrow_keys_in_the_posix_help_editor_keep_the_message(monkeypatch, bursts, helped, cancelled):
    keys = _Keys(*bursts)
    terminal, output = _posix_terminal(monkeypatch, keys)
    stopped = threading.Event()
    messages = []
    owner = ConsoleOwner(terminal, on_stop=stopped.set, on_help=messages.append)
    owner.start()
    assert stopped.wait(2)
    owner.join(2)
    text = "".join(output)
    assert messages == helped
    assert ("Help request cancelled." in text) is cancelled
    assert "Type S and press Enter to stop.\n" not in text


def _witness_cli(monkeypatch, console, agent):
    from hermeshands_device import cli, config, janitor, loop

    monkeypatch.setattr(cli, "TerminalConsole", lambda: console)
    monkeypatch.setattr(cli.sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(cli.sys, "stdout", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(config, "device_id", lambda: "device-1")
    monkeypatch.setattr(config, "gateway_url", lambda: "https://example.test/api/plugins/hermes-hands")
    monkeypatch.setattr(loop, "DeviceLoop", lambda **kwargs: agent)
    return cli, config, janitor


def test_s_right_after_y_still_prints_the_stop_line_and_saves_a_receipt(monkeypatch):
    from test_console import FakeConsole
    from test_lane_r3b2_console import _no_screen_witness_agent

    console = FakeConsole("Y")
    agent, _ = _no_screen_witness_agent(monkeypatch, console)
    cli, config, janitor = _witness_cli(monkeypatch, console, agent)

    def sweep_while_s_arrives(**kwargs):
        console.feed("S")
        assert agent.stop_event.wait(2)

    monkeypatch.setattr(janitor, "start", sweep_while_s_arrives)
    try:
        assert cli.main(["serve", "--witness"]) == 0
    finally:
        agent.client.close()
    assert "Session stopped. Nothing else will run on this computer.\n" in console.outputs
    assert len(list((config.ROOT / "receipts").glob("*.json"))) == 1
    assert console_module.SCREENSHOT_SESSION_PROMPT not in console.output()


@pytest.mark.parametrize("interrupted_in", ["witness_setup", "janitor", "serve_setup"])
def test_ctrl_c_while_the_agent_is_being_set_up_exits_without_a_traceback(monkeypatch, interrupted_in):
    from test_console import FakeConsole

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    console = FakeConsole("Y")
    cli, config, janitor = _witness_cli(monkeypatch, console, None)
    from hermeshands_device import loop

    monkeypatch.setattr(loop, "DeviceLoop", interrupt if interrupted_in != "janitor" else lambda **kwargs: pytest.fail("agent built"))
    monkeypatch.setattr(janitor, "start", interrupt if interrupted_in == "janitor" else lambda **kwargs: None)
    argv = ["serve", "--witness"] if interrupted_in == "witness_setup" else ["serve"]
    try:
        code = cli.main(argv)
    except KeyboardInterrupt:
        pytest.fail("Ctrl+C ended in a raw KeyboardInterrupt")
    assert code == 130
    if interrupted_in == "witness_setup":
        assert "wants to help with this computer" in console.output()
