import queue
import re
import signal
import sys
import threading
import time
import types

import pytest

from hermeshands_device import console as console_module
from hermeshands_device.console import ConsoleOwner


class FakeConsole:
    def __init__(self, *lines):
        self.lines = queue.Queue()
        self.outputs = []
        self.prompts = []
        self.reader_thread_ids = []
        self.read_started = threading.Event()
        self.lock = threading.Lock()
        self.partial_text = ""
        self.partial_started_at = None
        for line in lines:
            self.lines.put((line, None, None))

    def write(self, text):
        with self.lock:
            self.outputs.append(text)

    def read_line(self, prompt):
        with self.lock:
            self.prompts.append(prompt)
            self.reader_thread_ids.append(threading.get_ident())
        self.read_started.set()
        return self.lines.get()[0]

    def read_line_with_metadata(self, prompt, on_prompt_printed=None):
        with self.lock:
            self.prompts.append(prompt)
            self.reader_thread_ids.append(threading.get_ident())
        self.read_started.set()
        if on_prompt_printed is not None:
            on_prompt_printed()
        line, started_at, submitted_at = self.lines.get()
        submitted_at = submitted_at or time.monotonic()
        started_at = started_at or (submitted_at if line else None)
        return line, started_at, submitted_at

    def feed(self, line):
        submitted_at = time.monotonic()
        self.lines.put((line, submitted_at if line else None, submitted_at))

    def type_text(self, text):
        with self.lock:
            if not self.partial_text:
                self.partial_started_at = time.monotonic()
            self.partial_text += text

    def submit(self):
        with self.lock:
            line = self.partial_text
            started_at = self.partial_started_at
            self.partial_text = ""
            self.partial_started_at = None
        submitted_at = time.monotonic()
        self.lines.put((line, started_at, submitted_at))

    def discard_pending_line(self):
        with self.lock:
            self.partial_text = ""
            self.partial_started_at = None

    def output(self):
        with self.lock:
            return "".join(self.outputs)

    def prompt_text(self):
        with self.lock:
            return "".join(self.prompts)


def test_terminal_console_preserves_the_start_time_of_a_typed_line(monkeypatch):
    class FakeMsvcrt:
        characters = ["Y", "\r"]

        @classmethod
        def kbhit(cls):
            return bool(cls.characters)

        @classmethod
        def getwch(cls):
            return cls.characters.pop(0)

    timestamps = iter((10.0, 11.0))
    monkeypatch.setattr(console_module.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "msvcrt", FakeMsvcrt)
    monkeypatch.setattr(console_module.time, "monotonic", lambda: next(timestamps))
    console = console_module.TerminalConsole()
    console.write = lambda text: None

    line = console.read_line_with_metadata("Prompt: ")

    assert line.text == "Y"
    assert line.started_at == 10.0
    assert line.submitted_at == 11.0


@pytest.mark.parametrize("expire", [False, True])
def test_windows_prompt_discard_does_not_deadlock_the_input_ready_callback(monkeypatch, expire):
    keys = queue.Queue()
    monkeypatch.setattr(console_module.os, "name", "nt")
    monkeypatch.setitem(
        sys.modules,
        "msvcrt",
        types.SimpleNamespace(kbhit=lambda: not keys.empty(), getwch=keys.get_nowait),
    )
    console = console_module.TerminalConsole()
    initial_write = threading.Event()
    resume_write = threading.Event()
    discard_started = threading.Event()
    outputs = []

    def write(text):
        outputs.append(text)
        if not initial_write.is_set():
            initial_write.set()
            resume_write.wait(2)

    original_discard = console.discard_pending_line

    def discard():
        discard_started.set()
        original_discard()

    console.write = write
    console.discard_pending_line = discard
    owner = ConsoleOwner(console, on_stop=lambda: None, on_help=lambda text: None)
    answers = []
    request = threading.Thread(
        target=lambda: answers.append(
            owner.request("request", "Allow screenshot?", timeout=0.1 if expire else 2)
        ),
        daemon=True,
    )
    try:
        if not expire:
            owner.start()
            assert initial_write.wait(1)
        request.start()
        assert initial_write.wait(1)
        assert discard_started.wait(1)
        resume_write.set()
        if expire:
            request.join(1)
            assert not request.is_alive()
            assert answers == [None]
            assert any("No answer, so this was declined." in item for item in outputs)
        else:
            assert _wait_for(lambda: any("Allow screenshot?" in item for item in outputs))
            keys.put("Y")
            keys.put("\r")
            request.join(1)
            assert answers == ["Y"]
    finally:
        resume_write.set()
        console._input_generation_ack.set()
        keys.put("\x1a")
        request.join(1)
        owner.close()
        owner.join(1)


def _wait_for(predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


def test_console_owner_composes_help_and_lowercase_s_is_text():
    console = FakeConsole("H", "Please help me find the file.", "s")
    stopped = threading.Event()
    help_requests = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=help_requests.append)

    owner.start()

    assert stopped.wait(1)
    owner.join(1)
    assert help_requests == ["Please help me find the file."]


def test_help_composer_does_not_claim_request_is_ready_before_relay_reply():
    console = FakeConsole("H", "Please help me.")
    stopped = threading.Event()
    help_requests = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=help_requests.append)

    owner.start()

    assert _wait_for(lambda: help_requests)
    console.feed("S")
    assert stopped.wait(1)
    owner.join(1)
    assert "Help request ready." not in console.output()


def test_console_owner_timestamps_interactive_prompts():
    console = FakeConsole("S")
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)

    owner.start()

    assert stopped.wait(1)
    owner.join(1)
    assert re.match(
        r"^\d{2}:\d{2}  Type S and press Enter to stop, or H and press Enter to send a message: $",
        console.prompts[0],
    )


def test_console_eof_uses_the_stop_callback():
    console = FakeConsole(None)
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)

    owner.start()

    assert stopped.wait(1)
    owner.join(1)
    assert owner._closed is True


def test_startup_questions_and_interactive_input_have_one_owner_thread():
    console = FakeConsole("Y")
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    answers = []

    assert owner.startup_consent("Start? [Y/N]: ") == "Y"
    assert _wait_for(lambda: "Type S and press Enter to stop" in console.prompt_text())
    question = threading.Thread(
        target=lambda: answers.append(
            owner.request("session-screenshots", console_module.SCREENSHOT_SESSION_PROMPT, timeout=1)
        )
    )
    question.start()
    assert _wait_for(lambda: console_module.SCREENSHOT_SESSION_PROMPT in console.output())
    console.feed("Y")
    question.join(1)
    assert answers == ["Y"]
    console.feed("S")
    assert stopped.wait(1)

    owner.close()
    owner.join(1)
    assert len(set(console.reader_thread_ids)) == 1
    assert console.prompts[0] == "Start? [Y/N]: "


def test_terminal_console_returns_eof_when_stdin_closes(monkeypatch):
    reads = []
    restored = []

    class ClosedInput:
        def fileno(self):
            return 7

    def read(descriptor, count):
        reads.append((descriptor, count))
        if len(reads) > 1:
            raise RuntimeError("read repeated after EOF")
        return b""

    class Output:
        def __init__(self):
            self.text = []

        def write(self, text):
            self.text.append(text)

        def flush(self):
            return None

    termios = types.ModuleType("termios")
    termios.TCSANOW = 1
    termios.ICANON = 2
    termios.ECHO = 4
    termios.ISIG = 8
    termios.error = OSError
    termios.tcgetattr = lambda descriptor: [0, 0, 0, 31, 0, 0, []]
    termios.tcsetattr = lambda descriptor, when, state: restored.append((descriptor, when, state))
    tty = types.ModuleType("tty")
    tty.setraw = lambda descriptor: None
    output = Output()
    monkeypatch.setattr(console_module.os, "name", "posix")
    monkeypatch.setattr(console_module.sys, "stdin", ClosedInput())
    monkeypatch.setattr(console_module.os, "read", read)
    monkeypatch.setattr(console_module.sys, "stdout", output)
    monkeypatch.setitem(sys.modules, "termios", termios)
    monkeypatch.setitem(sys.modules, "tty", tty)

    assert console_module.TerminalConsole().read_line("Prompt: ") is None
    assert output.text == ["Prompt: "]
    assert restored == [(7, 1, [0, 0, 0, 17, 0, 0, []]), (7, 1, [0, 0, 0, 31, 0, 0, []])]


def test_startup_console_read_error_reaches_caller():
    class BrokenConsole:
        def write(self, text):
            return None

        def read_line(self, prompt):
            raise OSError("console read failed")

    owner = ConsoleOwner(BrokenConsole(), on_stop=lambda: None, on_help=lambda text: None)

    with pytest.raises(OSError, match="console read failed"):
        owner.startup_consent("Start?")

    owner.join(1)


@pytest.mark.parametrize("stop_key", ["S", "s"])
def test_uppercase_s_stops_help_editor_and_lowercase_s_is_text(stop_key):
    console = FakeConsole("H", stop_key, "S")
    stopped = threading.Event()
    help_requests = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=help_requests.append)

    owner.start()

    try:
        assert stopped.wait(1)
        owner.join(1)
        assert help_requests == ([] if stop_key == "S" else ["s"])
    finally:
        owner.close()
        console.feed(None)
        owner.join(1)


def test_escape_cancels_help_editor_without_stopping():
    console = FakeConsole("H", "\x1b", "S")
    stopped = threading.Event()
    help_requests = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=help_requests.append)

    owner.start()

    assert stopped.wait(1)
    owner.join(1)
    assert help_requests == []


def test_help_text_cannot_grant_a_screenshot_prompt():
    console = FakeConsole("H")
    stopped = threading.Event()
    help_requests = []
    answers = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=help_requests.append)
    owner.start()
    assert _wait_for(lambda: "Help message" in console.prompt_text())
    prompt = threading.Thread(
        target=lambda: answers.append(
            owner.request("screen-request", "Allow screenshot?", timeout=1)
        )
    )
    prompt.start()
    assert _wait_for(lambda: "Allow screenshot?" in console.output())
    assert re.search(r"\d{2}:\d{2}  Allow screenshot\?", console.output())
    console.feed("Y")
    prompt.join(1)
    assert answers == [""]
    assert help_requests == ["Y"]

    console.feed("S")
    assert stopped.wait(1)
    owner.join(1)


def test_h_starts_help_composer_during_a_screenshot_prompt():
    console = FakeConsole()
    stopped = threading.Event()
    help_requests = []
    answers = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=help_requests.append)
    owner.start()
    assert console.read_started.wait(1)
    prompt = threading.Thread(
        target=lambda: answers.append(
            owner.request("screen-request", "Allow screenshot?", timeout=1)
        )
    )
    prompt.start()
    assert _wait_for(lambda: "Allow screenshot?" in console.output())

    console.feed("H")
    assert _wait_for(lambda: "Help message" in console.prompt_text())
    console.feed("Please open the app.")
    prompt.join(1)
    assert answers == [""]
    assert _wait_for(lambda: help_requests)
    assert help_requests == ["Please open the app."]

    console.feed("S")
    assert stopped.wait(1)
    owner.join(1)


def test_late_answer_is_bound_to_expired_prompt_id():
    console = FakeConsole()
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)

    assert owner.request("old-request", "Allow screenshot?", timeout=0.02) is None
    console.feed("Y")
    answers = []
    later = threading.Thread(
        target=lambda: answers.append(
            owner.request("new-request", "Allow this screenshot?", timeout=1)
        )
    )
    later.start()
    assert _wait_for(lambda: "Allow this screenshot?" in console.output())
    console.feed("N")
    later.join(1)

    owner.close()
    console.feed(None)
    owner.join(1)
    assert answers == ["N"]
    assert "old-request" not in console.output()
    assert "Allow this screenshot?" in console.output()


def test_stop_during_screenshot_request_releases_prompt():
    console = FakeConsole()
    stopped = threading.Event()
    answers = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)
    request = threading.Thread(
        target=lambda: answers.append(
            owner.request("screen-request", "Allow this screenshot?", timeout=30)
        )
    )
    request.start()
    assert _wait_for(lambda: "Allow this screenshot?" in console.output())

    console.feed("S")
    request.join(1)
    owner.join(1)

    assert stopped.is_set()
    assert answers == ["S"]


def test_expired_queued_prompt_is_not_shown_later():
    console = FakeConsole()
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)
    first_answers = []
    first = threading.Thread(
        target=lambda: first_answers.append(
            owner.request("first-request", "First question?", timeout=1)
        )
    )
    first.start()
    assert _wait_for(lambda: "First question?" in console.output())

    assert owner.request("expired-request", "Expired question?", timeout=0.02) is None
    console.feed("Y")
    first.join(1)
    assert first_answers == ["Y"]
    assert _wait_for(lambda: len(console.reader_thread_ids) > 1)
    assert "expired-request" not in console.prompt_text()

    console.feed("S")
    assert stopped.wait(1)
    owner.join(1)


def test_expired_prompt_does_not_wedge_the_next_request():
    console = FakeConsole()
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)

    assert owner.request("expired-request", "Allow first screenshot?", timeout=0.2) is None
    answers = []
    later = threading.Thread(
        target=lambda: answers.append(
            owner.request("fresh-request", "Allow next screenshot?", timeout=2)
        )
    )
    later.start()
    assert _wait_for(lambda: "Allow next screenshot?" in console.output())
    assert re.search(r"\d{2}:\d{2}  No answer, so this was declined\.", console.output())

    console.feed("y")
    later.join(1)
    assert not later.is_alive()
    assert answers == ["y"]

    owner.close()
    console.feed(None)
    owner.join(1)


def test_line_submitted_before_fresh_prompt_cannot_answer_it():
    console = FakeConsole()
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)

    assert owner.request("expired-request", "Allow first screenshot?", timeout=0.2) is None
    console.feed("Y")
    answers = []
    later = threading.Thread(
        target=lambda: answers.append(
            owner.request("fresh-request", "Allow next screenshot?", timeout=2)
        )
    )
    later.start()
    assert _wait_for(lambda: "Allow next screenshot?" in console.output())
    assert not _wait_for(lambda: answers, timeout=0.05)

    console.feed("Y")
    later.join(1)
    assert not later.is_alive()
    assert answers == ["Y"]

    owner.close()
    console.feed(None)
    owner.join(1)


def test_line_started_before_fresh_prompt_cannot_answer_it():
    console = FakeConsole()
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)

    assert owner.request("expired-request", "Allow first screenshot?", timeout=0.2) is None
    answers = []
    later = threading.Thread(
        target=lambda: answers.append(
            owner.request("fresh-request", "Allow next screenshot?", timeout=2)
        )
    )
    later.start()
    assert _wait_for(lambda: "Allow next screenshot?" in console.output())
    with owner._lock:
        printed_at = owner._active.printed_at
    assert printed_at is not None

    console.lines.put(("Y", printed_at - 0.1, printed_at + 0.1))
    assert _wait_for(lambda: len(console.prompts) > 1)
    assert not answers

    console.feed("Y")
    later.join(1)
    assert not later.is_alive()
    assert answers == ["Y"]

    owner.close()
    console.feed(None)
    owner.join(1)


def test_half_typed_expired_answer_is_discarded_before_fresh_prompt():
    console = FakeConsole()
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)

    assert owner.request("expired-request", "Allow first screenshot?", timeout=0.2) is None
    console.type_text("Y")
    answers = []
    later = threading.Thread(
        target=lambda: answers.append(
            owner.request("fresh-request", "Allow next screenshot?", timeout=2)
        )
    )
    later.start()
    assert _wait_for(lambda: "Allow next screenshot?" in console.output())
    with console.lock:
        assert console.partial_text == ""

    console.submit()
    assert not _wait_for(lambda: answers == ["Y"], timeout=0.05)
    console.feed("Y")
    later.join(1)
    assert not later.is_alive()
    assert answers == [""]

    owner.close()
    console.feed(None)
    owner.join(1)


@pytest.mark.parametrize("command", ["S", "s", "H"])
def test_stop_and_help_commands_still_work_after_prompt_expiry(command):
    console = FakeConsole()
    stopped = threading.Event()
    help_requests = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=help_requests.append)
    owner.start()
    assert console.read_started.wait(1)

    assert owner.request("expired-request", "Allow screenshot?", timeout=0.2) is None
    console.feed(command)
    if command == "H":
        assert _wait_for(lambda: "Help message" in console.prompt_text())
        console.feed("Please help.")
        assert _wait_for(lambda: help_requests == ["Please help."])
        console.feed("S")
    assert stopped.wait(1)
    owner.join(1)
    assert help_requests == (["Please help."] if command == "H" else [])


@pytest.mark.parametrize("command", ["S", "s"])
def test_stop_during_fresh_prompt_after_expired_prompt(command):
    console = FakeConsole()
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)

    assert owner.request("expired-request", "Allow first screenshot?", timeout=0.2) is None
    answers = []
    later = threading.Thread(
        target=lambda: answers.append(
            owner.request("fresh-request", "Allow next screenshot?", timeout=2)
        )
    )
    later.start()
    assert _wait_for(lambda: "Allow next screenshot?" in console.output())

    console.feed(command)
    later.join(1)
    owner.join(1)
    assert stopped.is_set()
    assert answers == ["S"]


@pytest.mark.parametrize("label", ["", "telegram:123", "123", "discord:123", "\x1b[1A\x1b[2K123"])
def test_consent_never_exposes_platform_ids(label):
    text = console_module.witness_consent_copy(label, "example.test")
    assert text.startswith("Your helper wants to help with this computer.\n")
    assert "123" not in text
    assert "To stop at any time, type S and press Enter." in text


def test_sanitizer_removes_ansi_bidi_controls_and_caps_text():
    assert console_module.sanitize_text("\x1b[1A\x1b[2Kfile\u202e\u200d\x00\ud800") == "file"
    assert console_module.sanitize_text("a" * 2001, limit=2000) == "a" * 1997 + "..."


def test_lowercase_help_and_lone_s_is_message():
    console = FakeConsole("h", "s", "S")
    stopped = threading.Event()
    messages = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=messages.append)
    owner.start()
    assert stopped.wait(1)
    owner.join(1)
    assert messages == ["s"]
    assert "Stopping now...\n" in console.output()


def test_invalid_screenshot_answer_retries_without_spending_prompt():
    console = FakeConsole()
    owner = ConsoleOwner(console, on_stop=lambda: None, on_help=lambda text: None)
    answers = []
    worker = threading.Thread(
        target=lambda: answers.append(
            owner.request("private-hex-id", "Allow screenshot?", timeout=1)
        )
    )
    worker.start()
    assert _wait_for(lambda: "Allow screenshot?" in console.prompt_text())
    console.feed("\u043d")
    assert _wait_for(lambda: "Please type Y or N" in console.output())
    assert not answers
    console.feed("y")
    worker.join(1)
    owner.close()
    console.feed(None)
    owner.join(1)
    assert answers == ["y"]
    assert "private-hex-id" not in console.prompt_text() + console.output()


def test_consent_screen_text_is_exact():
    assert console_module.witness_consent_copy("Ridwan", "hands.example.test") == (
        "Ridwan wants to help with this computer.\n"
        "Ridwan can run commands and open or change your files, but only after Ridwan approves each one.\n"
        "Ridwan cannot move your mouse or type on your keyboard.\n"
        "Every command appears here before it runs.\n"
        "Screenshots: you will be asked each time.\n"
        "This ends by itself after 30 minutes.\n"
        "If Windows asks for permission, choose No unless Ridwan told you to expect it.\n"
        "To stop at any time, type S and press Enter.\n"
        "To send Ridwan a message, type H and press Enter.\n"
        "Details: hands.example.test\n"
    )
    assert console_module.WITNESS_START_PROMPT == "Start? Type Y or N, then press Enter: "
    fallback = console_module.witness_consent_copy("", "hands.example.test")
    assert fallback.startswith("Your helper wants to help with this computer.\n")
    assert (
        "Your helper can run commands and open or change your files, but only after your helper approves each one.\n"
        in fallback
    )
    assert "To send your helper a message, type H and press Enter.\n" in fallback


def test_terminal_console_write_strips_escapes_and_controls_but_keeps_newlines(monkeypatch):
    written = []
    monkeypatch.setattr(
        console_module.sys,
        "stdout",
        types.SimpleNamespace(write=written.append, flush=lambda: None),
    )
    console_module.TerminalConsole().write("10:29  Running: rm\x1b[1A\x1b[2K -rf \u202edir\x07\r\n")
    assert written == ["10:29  Running: rm -rf dir\n"]


def test_terminal_console_end_messages_tolerate_missing_stdout(monkeypatch):
    monkeypatch.setattr(console_module.sys, "stdout", None)
    terminal = console_module.TerminalConsole()

    terminal.write("Session stopped. Nothing else will run on this computer.\n")
    terminal.write(console_module.RECEIPT_SAVED.format(text_path="session.txt", json_path="session.json"))


@pytest.mark.parametrize("operation", ["write", "flush"])
def test_terminal_console_end_messages_tolerate_output_oserror(monkeypatch, operation):
    class ClosedOutput:
        def write(self, text):
            if operation == "write":
                raise OSError("terminal closed")

        def flush(self):
            if operation == "flush":
                raise OSError("terminal closed")

    monkeypatch.setattr(console_module.sys, "stdout", ClosedOutput())
    terminal = console_module.TerminalConsole()

    terminal.write("Session stopped. Nothing else will run on this computer.\n")
    terminal.write(console_module.RECEIPT_SAVED.format(text_path="session.txt", json_path="session.json"))


def test_console_owner_notice_prints_one_plain_line():
    console = FakeConsole()
    owner = ConsoleOwner(console, on_stop=lambda: None, on_help=lambda text: None)
    owner.notice("Lost connection to your helper.\x1b[2K Trying again.\u202e")
    assert console.output() == "\nLost connection to your helper. Trying again.\n"


def test_terminal_restore_runs_on_close_and_survives_termios_unload(monkeypatch):
    restored = []
    termios = types.ModuleType("termios")
    termios.TCSANOW = 1
    termios.ICANON = 2
    termios.ECHO = 4
    termios.ISIG = 8
    termios.error = OSError
    termios.tcgetattr = lambda descriptor: [0, 0, 0, 31, 0, 0, []]
    termios.tcsetattr = lambda descriptor, when, state: restored.append(state[3])
    monkeypatch.setattr(console_module.os, "name", "posix")
    monkeypatch.setattr(console_module.sys, "stdin", types.SimpleNamespace(fileno=lambda: 7))
    monkeypatch.setattr(console_module.os, "read", lambda descriptor, count: b"")
    monkeypatch.setattr(
        console_module.sys,
        "stdout",
        types.SimpleNamespace(write=lambda text: None, flush=lambda: None),
    )
    monkeypatch.setitem(sys.modules, "termios", termios)
    terminal = console_module.TerminalConsole()
    assert terminal.read_line("Prompt: ") is None
    restored.clear()
    monkeypatch.delitem(sys.modules, "termios")
    ConsoleOwner(terminal, on_stop=lambda: None, on_help=lambda text: None).close()
    assert restored == [31]


def test_eof_during_active_prompt_does_not_ask_for_y_or_n():
    console = FakeConsole()
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    answers = []
    worker = threading.Thread(target=lambda: answers.append(owner.request("screen-request", "Allow screenshot?", timeout=1)))
    worker.start()
    assert _wait_for(lambda: "Allow screenshot?" in console.prompt_text())
    console.feed(None)
    worker.join(1)
    owner.join(1)
    assert stopped.is_set()
    assert answers == [None]
    assert "Please type Y or N" not in console.output()


@pytest.mark.parametrize("command", ["S", "s"])
@pytest.mark.parametrize("editing_help", [False, True])
def test_stop_callback_precedes_prompt_release_and_stopping_output(command, editing_help):
    stopping_output = threading.Event()
    release_output = threading.Event()

    class SlowConsole(FakeConsole):
        def write(self, text):
            super().write(text)
            if text == "Stopping now...\n":
                stopping_output.set()
                release_output.wait(2)

    console = SlowConsole()
    stopped = threading.Event()
    messages = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=messages.append)
    answers = []

    def request():
        answer = owner.request("screen-request", "Allow screenshot?", timeout=2)
        answers.append((answer, stopped.is_set()))

    owner.start()
    assert console.read_started.wait(1)
    if editing_help:
        console.feed("H")
        assert _wait_for(lambda: "Help message" in console.prompt_text())
        command = "S"
    worker = threading.Thread(target=request, daemon=True)
    worker.start()
    try:
        assert _wait_for(lambda: "Allow screenshot?" in console.output())
        console.feed(command)
        assert stopping_output.wait(1)
        worker.join(1)
        assert answers == [("S", True)]
        assert messages == []
    finally:
        release_output.set()
        owner.close()
        console.feed(None)
        owner.join(1)
        worker.join(1)


@pytest.mark.parametrize("label", ["local", "LOCAL", "local owner", "Local Owner", "telegram: 123", "matrix2 : @person", "slack-user:"])
def test_legacy_machine_labels_display_as_your_helper(label):
    assert console_module.helper_label(label) == "your helper"
    assert console_module.witness_consent_copy(label, "example.test").startswith(
        "Your helper wants to help with this computer.\n"
    )


def test_human_helper_label_is_preserved_and_subject_is_capitalized():
    assert console_module.helper_label("ridwan") == "ridwan"
    assert console_module.witness_consent_copy("ridwan", "example.test").startswith(
        "Ridwan wants to help with this computer.\n"
    )


def test_atexit_registers_a_working_terminal_restore(monkeypatch):
    registered = []
    restored = []
    monkeypatch.setattr(console_module.atexit, "register", registered.append)
    terminal = console_module.TerminalConsole()
    termios = types.SimpleNamespace(
        TCSANOW=1,
        error=OSError,
        tcsetattr=lambda *args: restored.append(args),
    )
    state = [0, 0, 0, 31, 0, 0, []]
    terminal._terminal_state = (termios, 7, state)

    assert registered == [terminal.restore_terminal]
    registered[0]()
    assert restored == [(7, 1, state)]


@pytest.mark.parametrize("platform", ["posix", "nt"])
def test_sigterm_handler_lives_until_main_thread_close(monkeypatch, platform):
    changes = []
    previous = lambda signum, frame: None
    handlers = {signal.SIGTERM: previous}

    def set_handler(signum, handler):
        changes.append((signum, handler))
        old_handler = handlers[signum]
        handlers[signum] = handler
        return old_handler

    monkeypatch.setattr(console_module, "os", types.SimpleNamespace(name=platform))
    monkeypatch.setattr(signal, "signal", set_handler)
    monkeypatch.setattr(signal, "getsignal", handlers.__getitem__)
    terminal = console_module.TerminalConsole()
    terminal.read_line_with_metadata = lambda *args, **kwargs: console_module._ConsoleLine(None, None, time.monotonic())
    owner = ConsoleOwner(terminal, on_stop=lambda: None, on_help=lambda text: None)
    owner.start()
    try:
        owner.join(1)
        assert owner._closed
        if platform == "posix":
            assert len(changes) == 1
            assert changes[0][0] == signal.SIGTERM
            with pytest.raises(KeyboardInterrupt):
                changes[0][1](signal.SIGTERM, None)
        else:
            assert changes == []
    finally:
        owner.close()
    assert changes == ([(signal.SIGTERM, signal.default_int_handler), (signal.SIGTERM, previous)] if platform == "posix" else [])


def test_close_preserves_nested_shutdown_signal_handler_until_it_unwinds(monkeypatch):
    previous = lambda signum, frame: None
    handlers = {signal.SIGTERM: previous}

    def set_handler(signum, handler):
        old_handler = handlers[signum]
        handlers[signum] = handler
        return old_handler

    monkeypatch.setattr(console_module, "os", types.SimpleNamespace(name="posix"))
    monkeypatch.setattr(signal, "signal", set_handler)
    monkeypatch.setattr(signal, "getsignal", handlers.__getitem__)
    terminal = console_module.TerminalConsole()
    terminal.read_line_with_metadata = lambda *args, **kwargs: console_module._ConsoleLine(None, None, time.monotonic())
    owner = ConsoleOwner(terminal, on_stop=lambda: None, on_help=lambda text: None)
    owner.start()
    owner.join(1)
    assert owner._closed
    console_handler = handlers[signal.SIGTERM]

    set_handler(signal.SIGTERM, signal.SIG_IGN)
    owner.close()
    assert handlers[signal.SIGTERM] == signal.SIG_IGN

    set_handler(signal.SIGTERM, console_handler)
    owner.close()
    assert handlers[signal.SIGTERM] == previous
