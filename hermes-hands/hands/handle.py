"""``RemoteProcessHandle``: the ``ProcessHandle`` (``tools/environments/base_output.py:269-281``) for a
script running on a paired device, shaped like core's ``_ThreadedProcessHandle`` (``:284-338``).

A worker thread (started in a copy of the caller's context, so profile-scoped reads stay scoped)
queues the script at the relay and long-polls its output into an OS pipe whose read end is
``stdout``: a real descriptor, so core's drain thread uses its PeekNamedPipe/select path
(``base_output.py:342-477``). The write end is closed BEFORE ``poll()``/``returncode`` turn non-None;
the drain thread stops about 300 ms after exit, and output still in flight then would be lost
(``base.py:549-594``). There is deliberately no ``pid``: core's backstop kills ``pid`` as a host
process tree (``base.py:785-798``). Timeouts are core's: the device gets a later deadline, so
``poll()`` stays None past core's and core returns 124 with ``hermes_timed_out`` itself. With an
``inline_limit`` (terminal-tool calls only), output past it keeps its first and last halves around a
note naming the device's full log (PLAN-v3 §1.4 Output). Once the job is queued, losing the relay
never reads as "nothing ran": the job is cancelled best effort and the note says it may still run.
"""

from __future__ import annotations

import contextvars
import logging
import os
import threading

from . import client, messages
from .relay import UNREACHABLE

DEVICE_TIMEOUT_GRACE = 15  # seconds the device waits past core's deadline before its own 124
# Core's cwd and exit-status marker lines end every command's output (base_session_env.py:40-79):
# the kept tail always has room for them, however small inline_output_limit_bytes is set.
MIN_INLINE_LIMIT = 8192

logger = logging.getLogger(__name__)


class RemoteProcessHandle:
    def __init__(
        self,
        device: str,
        script: str,
        *,
        login: bool,
        timeout: int,
        inline_limit: int | None = None,
        stdin: str | None = None,
        file_op: bool = False,
    ):
        read_fd, write_fd = os.pipe()
        self._stdout = os.fdopen(read_fd, "r", encoding="utf-8-sig", errors="replace")
        self._write_fd = write_fd
        self._returncode: int | None = None
        self._done = threading.Event()
        self._lock = threading.Lock()
        self._job_id: str | None = None
        self._killed = False
        self._reader_gone = False
        self._wrote = False
        if inline_limit is not None:
            inline_limit = max(inline_limit, MIN_INLINE_LIMIT)
        self._head_left = None if inline_limit is None else inline_limit - inline_limit // 2
        self._tail_cap = 0 if inline_limit is None else inline_limit // 2
        self._tail = bytearray()
        self._omitted = 0
        worker = contextvars.copy_context()
        threading.Thread(
            target=worker.run,
            args=(self._run, device, script, login, timeout, stdin, file_op),
            name=f"hermes-hands-{device}",
            daemon=True,
        ).start()

    @property
    def stdout(self):
        return self._stdout

    @property
    def returncode(self) -> int | None:
        return self._returncode

    def poll(self) -> int | None:
        return self._returncode if self._done.is_set() else None

    def wait(self, timeout: float | None = None) -> int:
        """The exit code; ``UNREACHABLE`` if it is still running after ``timeout`` (the Protocol's
        ``-> int``, base_output.py:275, where Popen would raise TimeoutExpired)."""
        if not self._done.wait(timeout=timeout):
            return UNREACHABLE
        return self._returncode

    def kill(self) -> None:
        """Cancel the job at the relay (the device stops it at its next poll) and drop further output."""
        with self._lock:
            if self._killed:
                return
            self._killed = True
            job_id = self._job_id
        if job_id is not None and not self._done.is_set():
            self._cancel(job_id)

    @staticmethod
    def _cancel(job_id: str) -> None:
        try:
            client.cancel_job(job_id)
        except client.HandsError:
            logger.warning(
                "hermes-hands: could not cancel job %s at the relay", job_id, exc_info=True
            )

    def _write(self, text: str) -> None:
        self._write_bytes(text.encode("utf-8"))

    def _write_bytes(self, data: bytes) -> None:
        if not data or self._killed or self._reader_gone:
            return
        try:
            while data:
                data = data[os.write(self._write_fd, data) :]
        except OSError:
            self._reader_gone = True  # core closed stdout: nobody reads any more
        self._wrote = True

    def _write_notice(self, text: str) -> None:
        """A hands: line after the command's own output, on a line of its own."""
        self._write(("\n" if self._wrote else "") + text)

    def _emit(self, text: str) -> None:
        """Command output: straight through, or within the inline limit as head plus a rolling tail."""
        data = text.encode("utf-8")
        if self._head_left is None:
            self._write_bytes(data)
            return
        head, rest = data[: self._head_left], data[self._head_left :]
        self._head_left -= len(head)
        self._write_bytes(head)
        self._tail += rest
        excess = len(self._tail) - self._tail_cap
        if excess > 0:
            self._omitted += excess
            del self._tail[:excess]

    def _flush_tail(self, job_id: str | None) -> None:
        if self._omitted:
            self._write(f"\n{messages.output_omitted(self._omitted, job_id)}\n")
        self._write_bytes(bytes(self._tail))

    def _run(self, device: str, script: str, login: bool, timeout: int, stdin: str | None, file_op: bool) -> None:
        returncode, job_id, notice = UNREACHABLE, None, None
        try:
            job_id = client.start_job(
                device,
                script=script,
                login=login,
                timeout=timeout + DEVICE_TIMEOUT_GRACE,
                stdin=stdin,
                file_op=file_op,
            )
            with self._lock:
                self._job_id = job_id
                killed = self._killed
            if killed:
                self._cancel(job_id)
            after = 0
            while True:
                out = client.job_output(job_id, after)
                for chunk in out["chunks"]:
                    self._emit(chunk)
                after = out["next"]
                if out["done"]:
                    error = out.get("error")
                    notice = messages.device_result_error(str(error), device) if error else None
                    returncode = (
                        UNREACHABLE if out.get("returncode") is None else int(out["returncode"])
                    )
                    return
        except client.HandsError as exc:
            if job_id is None:
                notice = str(exc)
            else:
                logger.warning("hermes-hands: lost the relay during job %s: %s", job_id, exc)
                self._cancel(job_id)
                notice = messages.contact_lost(device)
        finally:
            self._flush_tail(job_id)
            if notice:
                self._write_notice(str(notice))
            os.close(self._write_fd)  # EOF reaches the drain thread before poll() reports the exit
            self._returncode = returncode
            self._done.set()
