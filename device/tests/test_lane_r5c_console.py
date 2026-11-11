import os
import sys
import threading
import time

import pytest

from hermeshands_device.console import ConsoleOwner
from test_lane_r4b_console import _Keys, _posix_terminal


class _TimedKeys(_Keys):
    """Each burst becomes readable a set number of seconds after the reader first asks for a key."""

    def __init__(self, *timed_bursts):
        super().__init__(*(burst for _, burst in timed_bursts))
        self.delays = [delay for delay, _ in timed_bursts]
        self.started = None

    def _ready_in(self):
        if self.started is None:
            self.started = time.monotonic()
        while self.bursts and not self.bursts[0]:
            self.bursts.pop(0)
            self.delays.pop(0)
        if not self.bursts:
            return None
        return self.started + self.delays[0] - time.monotonic()

    def read(self, count):
        ready_in = self._ready_in()
        if ready_in is None:
            return ""
        time.sleep(max(0.0, ready_in))
        return self.bursts[0].pop(0)

    def select(self, readers, writers, errors, timeout=None):
        ready_in = self._ready_in()
        if ready_in is None:
            return readers, [], []
        if timeout is not None and ready_in > timeout:
            time.sleep(timeout)
            return [], [], []
        time.sleep(max(0.0, ready_in))
        return readers, [], []


def _help_editor(monkeypatch, keys):
    terminal, output = _posix_terminal(monkeypatch, keys)
    stopped = threading.Event()
    messages = []
    owner = ConsoleOwner(terminal, on_stop=stopped.set, on_help=messages.append)
    owner.start()
    assert stopped.wait(3)
    owner.join(2)
    return messages, "".join(output)


@pytest.mark.parametrize("after_escape", ["S\n", "\x03", "\x04"])
def test_a_key_right_after_escape_is_not_eaten_in_the_help_editor(monkeypatch, after_escape):
    messages, text = _help_editor(monkeypatch, _Keys("H\n", "abc\x1b" + after_escape))
    assert messages == []
    assert "Help request cancelled." in text


@pytest.mark.parametrize(
    ("burst", "lines"),
    [
        ("ab\x1b\n", ["\x1b", ""]),
        ("ab\x1b\x1b", ["\x1b", "\x1b"]),
        ("ab\x1bxc\n", ["\x1b", "xc"]),
        ("ab\x1b[Dc\n", ["abc"]),
        ("ab\x1bODc\n", ["abc"]),
    ],
)
def test_only_a_real_sequence_introducer_is_swallowed_after_escape(monkeypatch, burst, lines):
    terminal, _ = _posix_terminal(monkeypatch, _Keys(burst))
    assert [terminal.read_line("Prompt: ") for _ in lines] == lines


def test_ctrl_c_right_after_escape_still_interrupts(monkeypatch):
    terminal, _ = _posix_terminal(monkeypatch, _Keys("ab\x1b\x03"))
    assert terminal.read_line("Prompt: ") == "\x1b"
    with pytest.raises(KeyboardInterrupt):
        terminal.read_line("Prompt: ")


def test_a_key_kept_after_escape_keeps_the_time_it_was_typed(monkeypatch):
    terminal, _ = _posix_terminal(monkeypatch, _Keys("\x1by\n"))
    first = terminal.read_line_with_metadata("Prompt: ")
    time.sleep(0.05)
    between = time.monotonic()
    second = terminal.read_line_with_metadata("Prompt: ")
    assert (first.text, second.text) == ("\x1b", "y")
    assert second.started_at < between


def test_an_arrow_key_split_by_a_slow_link_keeps_the_help_message(monkeypatch):
    keys = _TimedKeys((0, "H\n"), (0, "abc\x1b"), (0.15, "[Dd\n"), (0.3, "S\n"))
    messages, text = _help_editor(monkeypatch, keys)
    assert messages == ["abcd"]
    assert "Help request cancelled." not in text


def test_a_lone_escape_still_cancels_promptly(monkeypatch):
    keys = _TimedKeys((0, "H\n"), (0, "abc\x1b"), (2.5, "S\n"))
    terminal, output = _posix_terminal(monkeypatch, keys)
    cancelled = threading.Event()
    stopped = threading.Event()
    owner = ConsoleOwner(terminal, on_stop=stopped.set, on_help=lambda text: None)
    real_write = terminal.write

    def write(text):
        real_write(text)
        if "Help request cancelled." in text:
            cancelled.set()

    terminal.write = write
    started = time.monotonic()
    owner.start()
    assert cancelled.wait(2)
    assert time.monotonic() - started < 1.5
    assert stopped.wait(3)
    owner.join(2)


_PTY_READER = r"""
import sys
sys.path.insert(0, sys.argv[1])
from hermeshands_device.console import TerminalConsole
terminal = TerminalConsole()
for _ in range(int(sys.argv[2])):
    try:
        line = terminal.read_line("")
    except KeyboardInterrupt:
        line = "INTERRUPT"
    sys.stderr.write("LINE " + repr(line) + "\n")
    sys.stderr.flush()
"""


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX pseudo-terminal")
@pytest.mark.parametrize(
    ("chunks", "lines"),
    [
        ((b"my text\x1bS\n",), ["'\\x1b'", "'S'"]),
        ((b"msg", b"\x1b", 0.03, b"S", 0.03, b"\n"), ["'\\x1b'", "'S'"]),
        ((b"ab\x1b\x03",), ["'\\x1b'", "'INTERRUPT'"]),
        ((b"abc\x1b", 0.15, b"[Dd\n"), ["'abcd'"]),
        ((b"abc\x1b[Dd\n",), ["'abcd'"]),
    ],
)
def test_escape_handling_through_a_real_pty(chunks, lines):
    import pty
    import subprocess
    import termios

    device = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [sys.executable, "-c", _PTY_READER, device, str(len(lines))],
        stdin=slave,
        stdout=slave,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while termios.tcgetattr(slave)[3] & termios.ICANON and time.monotonic() < deadline:
            time.sleep(0.01)
        for chunk in chunks:
            if isinstance(chunk, float):
                time.sleep(chunk)
            else:
                os.write(master, chunk)
        _, errors = process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
        os.close(master)
        os.close(slave)
    found = [line[5:] for line in errors.decode().splitlines() if line.startswith("LINE ")]
    assert found == lines
