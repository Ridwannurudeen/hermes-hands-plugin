from __future__ import annotations

import atexit
import codecs
import os
import re
import select
import signal
import unicodedata
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Protocol


WITNESS_CAPABILITIES = ("witness-v1", "checkup-v1", "help-v1", "receipt-v1")
WITNESS_START_PROMPT = "Start? Type Y or N, then press Enter: "
SCREENSHOT_SESSION_PROMPT = "Allow screenshot requests this session?"
WITNESS_CONSOLE_CLOSED = "Witness mode declined because the console closed.\n"
WITNESS_DECLINED = "Witness mode declined. No session was started.\n"
WITNESS_STOPPED_BEFORE_START = "Witness mode stopped before the session started.\n"
SCREENSHOTS_DISABLED = "OK. No screenshots this session.\n"
RECEIPT_SAVED = "Your record of this session: {text_path}\nJSON: {json_path}\n"
_EXTENDED_SCAN_CODES = frozenset("GHIKMOPQRSstuvw\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x91\x92\x93\x94")
_ESCAPE_SEQUENCE_WAIT = 0.5


def sanitize_text(value: str, *, limit: int | None = None, keep: str = "") -> str:
    value = re.sub(r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~]|[@-_])", "", value)
    value = "".join(
        char for char in value if char in keep or unicodedata.category(char) not in ("Cc", "Cf", "Cs", "Zl", "Zp")
    )
    if limit is not None and len(value) > limit:
        value = value[:max(0, limit - 3)] + "..."
    return value


def helper_label(value: str | None) -> str:
    label = sanitize_text(value or "", limit=80).strip()
    if (
        not label
        or label.casefold() in ("local", "local owner")
        or label.isdecimal()
        or re.match(r"^[A-Za-z][A-Za-z0-9_-]*\s*:", label)
    ):
        return "your helper"
    return label


def _timestamped(text: str) -> str:
    return f"{datetime.now().strftime('%H:%M')}  {text}"


def witness_consent_copy(owner_label: str, gateway_host: str) -> str:
    label = helper_label(owner_label)
    subject = label[:1].upper() + label[1:]
    return (
        f"{subject} wants to help with this computer.\n"
        f"{subject} can run commands and open or change your files, but only after {label} approves each one.\n"
        f"{subject} cannot move your mouse or type on your keyboard.\n"
        "Every command appears here before it runs.\n"
        "Screenshots: you will be asked each time.\n"
        "This ends by itself after 30 minutes.\n"
        f"If Windows asks for permission, choose No unless {label} told you to expect it.\n"
        "To stop at any time, type S and press Enter.\n"
        f"To send {label} a message, type H and press Enter.\n"
        f"Details: {sanitize_text(gateway_host)}\n"
    )


class ConsoleInput(Protocol):
    def write(self, text: str) -> None: ...

    def read_line(self, prompt: str) -> str | None: ...


@dataclass(frozen=True)
class _ConsoleLine:
    text: str | None
    started_at: float | None
    submitted_at: float


class TerminalConsole:
    def __init__(self):
        self._write_lock = threading.Lock()
        self._input_lock = threading.Lock()
        self._current_line: list[tuple[str, float]] | None = None
        self._input_generation = 0
        self._input_generation_ack = threading.Event()
        self._pending_lines: deque[_ConsoleLine] = deque()
        self._terminal_state = None
        self._terminal_lock = threading.Lock()
        self._key_after_escape: tuple[str, float] | None = None
        atexit.register(self.restore_terminal)

    def write(self, text: str) -> None:
        self._write_raw(sanitize_text(text, keep="\n\t"))

    def _write_raw(self, text: str) -> None:
        with self._write_lock:
            output = sys.stdout
            if output is None:
                return
            try:
                output.write(text)
                output.flush()
            except OSError:
                return

    def read_line(self, prompt: str) -> str | None:
        return self.read_line_with_metadata(prompt).text

    def read_line_with_metadata(
        self,
        prompt: str,
        *,
        on_prompt_printed: Callable[[], None] | None = None,
    ) -> _ConsoleLine:
        with self._input_lock:
            if self._pending_lines:
                return self._pending_lines.popleft()
            characters: list[tuple[str, float]] = []
            self._current_line = characters
            reader_generation = self._input_generation
        self.write(prompt)
        if on_prompt_printed is not None:
            on_prompt_printed()

        def finish(text: str | None, submitted_at: float) -> _ConsoleLine:
            with self._input_lock:
                started_at = characters[0][1] if characters else None
                if self._current_line is characters:
                    self._current_line = None
            return _ConsoleLine(text, started_at, submitted_at)

        try:
            if os.name == "nt":
                import msvcrt

                def process_character(character: str, character_at: float, *, echo: bool) -> _ConsoleLine | None:
                    if character in ("\x00", "\xe0"):
                        scan_code = msvcrt.getwch()
                        if character == "\x00" or scan_code in _EXTENDED_SCAN_CODES:
                            return None
                        with self._input_lock:
                            characters.append((character, character_at))
                        if echo:
                            self.write(character)
                        character = scan_code
                    if character == "\x1a":
                        return _ConsoleLine(None, None, character_at)
                    if character in ("\r", "\n"):
                        with self._input_lock:
                            started_at = characters[0][1] if characters else None
                            text = "".join(char for char, _ in characters)
                            characters.clear()
                        if echo:
                            self.write("\n")
                        return _ConsoleLine(text, started_at, character_at)
                    if character == "\x1b":
                        with self._input_lock:
                            started_at = characters[0][1] if characters else character_at
                            characters.clear()
                        if echo:
                            self.write("\n")
                        return _ConsoleLine(character, started_at, character_at)
                    if character == "\x03":
                        raise KeyboardInterrupt
                    if character in ("\b", "\x7f"):
                        with self._input_lock:
                            if characters:
                                characters.pop()
                                if echo:
                                    self._write_raw("\b \b")
                        return None
                    with self._input_lock:
                        characters.append((character, character_at))
                    if echo:
                        self.write(character)
                    return None

                while True:
                    with self._input_lock:
                        generation = self._input_generation
                    if generation != reader_generation:
                        while msvcrt.kbhit():
                            character = msvcrt.getwch()
                            line = process_character(character, time.monotonic(), echo=False)
                            if line is not None:
                                with self._input_lock:
                                    self._pending_lines.append(line)
                        with self._input_lock:
                            if self._input_generation != generation:
                                continue
                            characters.clear()
                            reader_generation = generation
                            self._input_generation_ack.set()
                            line = self._pending_lines.popleft() if self._pending_lines else None
                        if line is not None:
                            return line
                        continue
                    if not msvcrt.kbhit():
                        time.sleep(0.01)
                        continue
                    character = msvcrt.getwch()
                    character_at = time.monotonic()
                    line = process_character(character, character_at, echo=True)
                    if line is not None:
                        with self._input_lock:
                            if self._current_line is characters:
                                self._current_line = None
                        return line

            import termios

            with self._terminal_lock:
                descriptor = sys.stdin.fileno()
                if self._terminal_state is None:
                    self._terminal_state = (termios, descriptor, termios.tcgetattr(descriptor))
                previous = self._terminal_state[2]
                current = previous.copy()
                current[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
                termios.tcsetattr(descriptor, termios.TCSANOW, current)
            decoder = codecs.getincrementaldecoder(getattr(sys.stdin, "encoding", None) or "utf-8")(errors="replace")

            def read_character(timeout: float | None = None) -> str | None:
                while True:
                    if timeout is not None and not select.select([descriptor], [], [], timeout)[0]:
                        return None
                    data = os.read(descriptor, 1)
                    if not data:
                        return ""
                    character = decoder.decode(data)
                    if character:
                        return character

            try:
                escape_state = None
                while True:
                    if self._key_after_escape is not None:
                        character, character_at = self._key_after_escape
                        self._key_after_escape = None
                    else:
                        character = read_character()
                        character_at = time.monotonic()
                    if character in ("", "\x04"):
                        return finish(None, character_at)
                    if escape_state is not None:
                        if escape_state == "csi" and " " <= character <= "?":
                            continue
                        final = "@" <= character <= "~"
                        escape_state = None
                        if final:
                            continue
                    if character in ("\r", "\n"):
                        self.write("\n")
                        return finish("".join(char for char, _ in characters), character_at)
                    if character == "\x1b":
                        following = read_character(_ESCAPE_SEQUENCE_WAIT)
                        if following in ("[", "O"):
                            escape_state = "csi" if following == "[" else "ss3"
                            continue
                        if following:
                            self._key_after_escape = (following, time.monotonic())
                        self.write("\n")
                        return finish(character, character_at)
                    if character == "\x03":
                        raise KeyboardInterrupt
                    if character in ("\b", "\x7f"):
                        with self._input_lock:
                            if characters:
                                characters.pop()
                                self._write_raw("\b \b")
                        continue
                    with self._input_lock:
                        characters.append((character, character_at))
                    self.write(character)
            finally:
                self.restore_terminal()
        finally:
            with self._input_lock:
                if self._current_line is characters:
                    self._current_line = None
                self._input_generation_ack.set()

    def restore_terminal(self) -> None:
        with self._terminal_lock:
            if self._terminal_state is None:
                return
            termios, descriptor, state = self._terminal_state
            try:
                termios.tcsetattr(descriptor, termios.TCSANOW, state)
            except (OSError, termios.error):
                # The terminal may already be gone during interpreter shutdown.
                return

    def discard_pending_line(self) -> None:
        with self._input_lock:
            if self._current_line is None:
                return
            if os.name != "nt":
                self._current_line.clear()
                return
            self._input_generation += 1
            self._input_generation_ack.clear()
        self._input_generation_ack.wait()


@dataclass
class _Prompt:
    prompt_id: str
    text: str
    ready: threading.Event = field(default_factory=threading.Event)
    answer: str | None = None
    expired: bool = False
    printed_at: float | None = None
    shown: bool = False
    timeout: float | None = None


class ConsoleOwner:
    def __init__(self, console: ConsoleInput, *, on_stop: Callable[[], None], on_help: Callable[[str], None]):
        self.console = console
        self.on_stop = on_stop
        self.on_help = on_help
        self._lock = threading.Lock()
        self._queued: deque[_Prompt] = deque()
        self._active: _Prompt | None = None
        self._reading = False
        self._read_prompt: _Prompt | None = None
        self._command_prompt: str | None = None
        self._command_prompt_shown = False
        self._thread: threading.Thread | None = None
        self._closed = False
        self._stopped = False
        self._sigterm_installed = False
        self._previous_sigterm_handler = None
        self._startup_ready = threading.Event()
        self._startup_resume = threading.Event()
        self._startup_answer: str | None = None
        self._startup_error: Exception | None = None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None or self._closed:
                return
            self._install_sigterm_handler()
            self._thread = threading.Thread(target=self._run, name="hermes-hands-console", daemon=True)
            self._thread.start()

    def startup_consent(self, consent_prompt: str) -> str | None:
        with self._lock:
            if self._thread is not None or self._closed:
                raise RuntimeError("console owner has already started")
            self._install_sigterm_handler()
            self._thread = threading.Thread(
                target=self._run_startup,
                args=(consent_prompt,),
                name="hermes-hands-console",
                daemon=True,
            )
            self._thread.start()
        try:
            self._startup_ready.wait()
        except KeyboardInterrupt:
            self._stop()
            raise
        if self._startup_error is not None:
            raise self._startup_error
        return self._startup_answer

    def request(self, prompt_id: str, text: str, *, timeout: float | None = None) -> str | None:
        prompt = _Prompt(prompt_id, text, timeout=timeout)
        with self._lock:
            if self._closed:
                return None
            active_ids = {item.prompt_id for item in self._queued}
            if self._active is not None:
                active_ids.add(self._active.prompt_id)
            if prompt_id in active_ids:
                raise ValueError(f"prompt ID is already active: {prompt_id}")
            self._queued.append(prompt)
            self._promote_locked()
            if self._active is prompt and self._reading and self._read_prompt is None:
                self._show_prompt_locked(prompt)
        self._startup_resume.set()
        self.start()
        if not prompt.ready.wait(timeout):
            with self._lock:
                if prompt.ready.is_set():
                    return prompt.answer
                prompt.expired = True
                if self._active is prompt:
                    self._active = None
                    if self._read_prompt is prompt:
                        self._read_prompt = None
                    self._promote_locked()
                elif prompt in self._queued:
                    self._queued.remove(prompt)
                self._announce_expired_locked()
            return None
        return prompt.answer

    def close(self) -> None:
        if (
            self._sigterm_installed
            and threading.current_thread() is threading.main_thread()
            and signal.getsignal(signal.SIGTERM) is signal.default_int_handler
        ):
            signal.signal(signal.SIGTERM, self._previous_sigterm_handler)
            self._sigterm_installed = False
        with self._lock:
            if self._closed:
                return
            self._closed = True
            pending = list(self._queued)
            self._queued.clear()
            if self._active is not None:
                pending.append(self._active)
                self._active = None
            for prompt in pending:
                prompt.answer = "S" if self._stopped else None
                prompt.ready.set()
            self._startup_resume.set()
        restore = getattr(self.console, "restore_terminal", None)
        if callable(restore):
            restore()

    def _install_sigterm_handler(self) -> None:
        if (
            os.name == "posix"
            and isinstance(self.console, TerminalConsole)
            and threading.current_thread() is threading.main_thread()
        ):
            self._previous_sigterm_handler = signal.signal(signal.SIGTERM, signal.default_int_handler)
            self._sigterm_installed = True

    def notice(self, text: str) -> None:
        with self._lock:
            if self._closed:
                return
            self.console.write(f"\n{sanitize_text(text)}\n")

    def join(self, timeout: float | None = None) -> None:
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def _promote_locked(self) -> None:
        if self._active is None and self._queued:
            self._active = self._queued.popleft()

    def _discard_pending_line(self) -> None:
        discard = getattr(self.console, "discard_pending_line", None)
        if callable(discard):
            discard()

    def _prompt_text(self, prompt: _Prompt) -> str:
        seconds = f" ({prompt.timeout:g} seconds)" if prompt.timeout is not None else ""
        return f"{sanitize_text(prompt.text)} Type Y or N, then Enter{seconds}: "

    def _show_prompt_locked(self, prompt: _Prompt) -> None:
        if self._closed or self._active is not prompt or prompt.expired:
            return
        self._lock.release()
        try:
            self._discard_pending_line()
        finally:
            self._lock.acquire()
        if self._closed or self._active is not prompt or prompt.expired:
            return
        self.console.write(f"\n{_timestamped(self._prompt_text(prompt))}\n")
        prompt.printed_at = time.monotonic()
        prompt.shown = True
        self._command_prompt_shown = False
        if self._reading and self._read_prompt is None:
            self._read_prompt = prompt

    def _announce_expired_locked(self) -> None:
        self._lock.release()
        try:
            self._discard_pending_line()
        finally:
            self._lock.acquire()
        if self._closed:
            return
        output = f"\n{_timestamped('No answer, so this was declined.')}\n"
        next_prompt = None
        if self._reading and self._read_prompt is None:
            if self._active is not None:
                output += f"\n{_timestamped(self._prompt_text(self._active))}\n"
                next_prompt = self._active
                self._read_prompt = self._active
            elif self._command_prompt is not None:
                output += f"{_timestamped(self._command_prompt)}"
                self._command_prompt_shown = True
        self.console.write(output)
        if next_prompt is not None:
            next_prompt.printed_at = time.monotonic()
            next_prompt.shown = True

    def _deliver_prompt(self, prompt: _Prompt, answer: str | None) -> None:
        with self._lock:
            if self._closed:
                return
            if self._active is prompt:
                self._active = None
            if not prompt.expired:
                prompt.answer = answer
                prompt.ready.set()
            self._promote_locked()

    def _read_console_line(self, text: str, on_prompt_printed: Callable[[], None]) -> _ConsoleLine:
        read_with_metadata = getattr(self.console, "read_line_with_metadata", None)
        if callable(read_with_metadata):
            line = read_with_metadata(text, on_prompt_printed=on_prompt_printed)
            if isinstance(line, _ConsoleLine):
                return line
            answer, started_at, submitted_at = line
            return _ConsoleLine(answer, started_at, submitted_at)
        on_prompt_printed()
        answer = self.console.read_line(text)
        submitted_at = time.monotonic()
        return _ConsoleLine(answer, submitted_at if answer else None, submitted_at)

    def _read_line(self, command_prompt: str) -> tuple[str | None, _Prompt | None]:
        with self._lock:
            if self._closed:
                return None, None
            self._promote_locked()
            prompt = self._active
            self._read_prompt = prompt
            self._reading = True
            self._command_prompt = command_prompt
            text = self._prompt_text(prompt) if prompt and not prompt.shown else command_prompt
            if (prompt is not None and prompt.shown) or (prompt is None and self._command_prompt_shown):
                text = ""

        def on_prompt_printed() -> None:
            with self._lock:
                if prompt is None:
                    if self._read_prompt is None:
                        self._command_prompt_shown = True
                elif self._active is prompt and not prompt.shown:
                    prompt.printed_at = time.monotonic()
                    prompt.shown = True

        try:
            line = self._read_console_line(_timestamped(text) if text else "", on_prompt_printed)
        except KeyboardInterrupt:
            with self._lock:
                self._reading = False
                self._read_prompt = None
            self.on_stop()
            self.close()
            return None, prompt
        except Exception:
            with self._lock:
                self._reading = False
                self._read_prompt = None
            self.on_stop()
            self.close()
            raise
        with self._lock:
            prompt = self._read_prompt
            self._read_prompt = None
            self._reading = False
            self._command_prompt_shown = False
            closed = self._closed
        if closed:
            return None, prompt
        if line.text is not None and prompt is not None:
            if (
                prompt.expired
                or prompt is not self._active
                or prompt.printed_at is None
                or (line.started_at is not None and line.started_at < prompt.printed_at)
                or line.submitted_at < prompt.printed_at
            ):
                prompt = None
        if line.text is None:
            if prompt is not None:
                self._deliver_prompt(prompt, None)
            self.on_stop()
            self.close()
        return line.text, prompt

    def _stop(self) -> None:
        with self._lock:
            if self._closed or self._stopped:
                return
            self._stopped = True
        self.on_stop()
        self.close()
        self.console.write("Stopping now...\n")

    def _run_startup(self, consent_prompt: str) -> None:
        consent = None
        try:
            consent = self.console.read_line(consent_prompt)
        except KeyboardInterrupt:
            consent = None
        except Exception as exc:
            self._startup_error = exc
            self._startup_ready.set()
            self.close()
            return
        if consent is None or consent.strip() in ("S", "s"):
            self.on_stop()
        self._startup_answer = consent
        self._startup_ready.set()
        if consent is None or consent.strip().casefold() != "y":
            self._startup_resume.wait()
        if not self._closed:
            self._run()

    def _edit_help(self) -> None:
        while not self._closed:
            text, prompt = self._read_line("Help message, or Escape to cancel: ")
            if text is not None and text.strip() == "S":
                self._stop()
                return
            if prompt is not None:
                if text == "\x1b":
                    self._deliver_prompt(prompt, "")
                    self.console.write("Help request cancelled.\n")
                    return
                self._deliver_prompt(prompt, "")
            if text is None:
                return
            if text == "\x1b":
                self.console.write("Help request cancelled.\n")
                return
            if not text:
                self.console.write("Help message cannot be empty.\n")
                continue
            self.on_help(text)
            self.console.write("Help request queued for sending.\n")
            return

    def _run(self) -> None:
        while not self._closed:
            line, prompt = self._read_line("Type S and press Enter to stop, or H and press Enter to send a message: ")
            if line is not None:
                line = line.strip()
            if prompt is not None:
                if line in ("S", "s"):
                    self._stop()
                    return
                if line is None:
                    return
                if line not in ("Y", "y", "N", "n", "H", "h", ""):
                    self.console.write("Please type Y or N\n")
                    continue
                self._deliver_prompt(prompt, "" if line in ("H", "h") else line)
                if line in ("H", "h"):
                    self._edit_help()
                continue
            if line is None:
                return
            if line in ("S", "s"):
                self._stop()
                return
            if line in ("H", "h"):
                self._edit_help()
            elif line:
                self.console.write("Type S and press Enter to stop.\n")
