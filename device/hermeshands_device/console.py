from __future__ import annotations

import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol


WITNESS_CAPABILITIES = ("witness-v1", "checkup-v1", "help-v1", "receipt-v1")
WITNESS_START_PROMPT = "Start witness mode? [Y/N]: "
SCREENSHOT_SESSION_PROMPT = "Allow screenshot requests this session?"
SCREENSHOT_REQUEST_PROMPT = "Allow this screenshot?"
WITNESS_CONSOLE_CLOSED = "Witness mode declined because the console closed.\n"
WITNESS_DECLINED = "Witness mode declined. No session was started.\n"
WITNESS_STOPPED_BEFORE_START = "Witness mode stopped before the session started.\n"
SCREENSHOTS_DISABLED = "Screenshot requests are disabled for this session.\n"
RECEIPT_SAVED = "Local receipts saved:\nText: {text_path}\nJSON: {json_path}\n"


def _timestamped(text: str) -> str:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return f"[{timestamp}] {text}"


def witness_consent_copy(owner_label: str, gateway_host: str) -> str:
    owner_label = "".join(char for char in owner_label if char.isprintable()).strip()[:80]
    owner_label = owner_label or "paired owner"
    return (
        f"{owner_label}'s Hermes wants to help\n"
        f"Gateway: {gateway_host}\n"
        "Session limit: 30 minutes\n"
        f"Capabilities: {', '.join(WITNESS_CAPABILITIES)}\n"
        "No mouse or keyboard control.\n"
        "Commands and outcomes are recorded.\n"
        "Screenshots require separate session and request consent.\n"
        "Press S or s to stop.\n"
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

    def write(self, text: str) -> None:
        with self._write_lock:
            sys.stdout.write(text)
            sys.stdout.flush()

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
                        msvcrt.getwch()
                        return None
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
                                    self.write("\b \b")
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
            import tty

            descriptor = sys.stdin.fileno()
            previous = termios.tcgetattr(descriptor)
            try:
                tty.setraw(descriptor)
                while True:
                    character = sys.stdin.read(1)
                    character_at = time.monotonic()
                    if character in ("", "\x04"):
                        return finish(None, character_at)
                    if character in ("\r", "\n"):
                        self.write("\n")
                        return finish("".join(char for char, _ in characters), character_at)
                    if character == "\x1b":
                        self.write("\n")
                        return finish(character, character_at)
                    if character == "\x03":
                        raise KeyboardInterrupt
                    if character in ("\b", "\x7f"):
                        with self._input_lock:
                            if characters:
                                characters.pop()
                                self.write("\b \b")
                        continue
                    with self._input_lock:
                        characters.append((character, character_at))
                    self.write(character)
            finally:
                termios.tcsetattr(descriptor, termios.TCSADRAIN, previous)
        finally:
            with self._input_lock:
                if self._current_line is characters:
                    self._current_line = None
                self._input_generation_ack.set()

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
        self._startup_ready = threading.Event()
        self._startup_resume = threading.Event()
        self._startup_answer: str | None = None
        self._startup_error: Exception | None = None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None or self._closed:
                return
            self._thread = threading.Thread(target=self._run, name="hermes-hands-console", daemon=True)
            self._thread.start()

    def startup_consent(self, consent_prompt: str) -> str | None:
        with self._lock:
            if self._thread is not None or self._closed:
                raise RuntimeError("console owner has already started")
            self._thread = threading.Thread(
                target=self._run_startup,
                args=(consent_prompt,),
                name="hermes-hands-console",
                daemon=True,
            )
            self._thread.start()
        self._startup_ready.wait()
        if self._startup_error is not None:
            raise self._startup_error
        return self._startup_answer

    def request(self, prompt_id: str, text: str, *, timeout: float | None = None) -> str | None:
        prompt = _Prompt(prompt_id, text)
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
                prompt.answer = None
                prompt.ready.set()
            self._startup_resume.set()

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
        return f"[{prompt.prompt_id}] {prompt.text} [Y/N]: "

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
        self.on_stop()
        self.close()

    def _run_startup(self, consent_prompt: str) -> None:
        consent = None
        try:
            consent = self.console.read_line(_timestamped(consent_prompt))
        except KeyboardInterrupt:
            consent = None
        except Exception as exc:
            self._startup_error = exc
            self._startup_ready.set()
            self.close()
            return
        if consent is None:
            self.on_stop()
        self._startup_answer = consent
        self._startup_ready.set()
        self._startup_resume.wait()
        if not self._closed:
            self._run()

    def _edit_help(self) -> None:
        while not self._closed:
            text, prompt = self._read_line("Help message, or Escape to cancel: ")
            if prompt is not None:
                if text in ("S", "s"):
                    self._deliver_prompt(prompt, "")
                    self._stop()
                    return
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
            if text in ("S", "s"):
                self._stop()
                return
            if not text:
                self.console.write("Help message cannot be empty.\n")
                continue
            self.on_help(text)
            self.console.write("Help request queued for sending.\n")
            return

    def _run(self) -> None:
        while not self._closed:
            line, prompt = self._read_line("Press S to stop or H to ask for help: ")
            if prompt is not None:
                if line in ("S", "s"):
                    self._deliver_prompt(prompt, line)
                    self._stop()
                    return
                self._deliver_prompt(prompt, "" if line == "H" else line)
                if line == "H":
                    self._edit_help()
                continue
            if line is None:
                return
            if line in ("S", "s"):
                self._stop()
                return
            if line == "H":
                self._edit_help()
