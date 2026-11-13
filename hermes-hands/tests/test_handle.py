import os
import threading
import time

import pytest

from hands import handle as handle_module
from hands import messages
from hands.handle import RemoteProcessHandle
from hands.relay import UNREACHABLE

client = handle_module.client


class FakeRelay:
    """Stands in for the loopback client; ``outputs`` are dicts or exceptions, served in order."""

    def __init__(self, outputs, *, start_error=None):
        self.outputs = list(outputs)
        self.start_error = start_error
        self.started = []
        self.cancelled = []
        self.release = threading.Event()
        self.release.set()

    def start_job(self, device, *, script, login, timeout, stdin=None, file_op=False):
        self.started.append((device, script, login, timeout))
        self.stdin = stdin
        self.file_op = file_op
        if self.start_error is not None:
            raise self.start_error
        return "job1"

    def job_output(self, job_id, after):
        assert job_id == "job1"
        self.release.wait(5)
        item = self.outputs.pop(0)
        if isinstance(item, Exception):
            raise item
        return {"returncode": None, "error": None, "png_b64": None, **item}

    def cancel_job(self, job_id):
        self.cancelled.append(job_id)


@pytest.fixture
def fake(monkeypatch):
    def install(outputs, **kwargs):
        relay = FakeRelay(outputs, **kwargs)
        for name in ("start_job", "job_output", "cancel_job"):
            monkeypatch.setattr(client, name, getattr(relay, name))
        return relay

    return install


def read_to_eof(proc, timeout=2.0) -> bytes:
    """Read stdout's descriptor to EOF on a thread; fails if EOF does not arrive in ``timeout``."""
    data, finished = [], threading.Event()

    def reader():
        fd = proc.stdout.fileno()
        while chunk := os.read(fd, 4096):
            data.append(chunk)
        finished.set()

    threading.Thread(target=reader, daemon=True).start()
    assert finished.wait(timeout), "stdout did not reach EOF"
    return b"".join(data)


def wait_exit(proc, timeout=5.0) -> int:
    deadline = time.monotonic() + timeout
    while proc.poll() is None:
        assert time.monotonic() < deadline, "handle never exited"
        time.sleep(0.005)
    return proc.returncode


def test_write_end_closes_before_exit_is_visible(fake):
    relay = fake(
        [
            {"chunks": ["hello ", "wörld"], "next": 2, "done": False},
            {"chunks": ["\n"], "next": 3, "done": True, "returncode": 3},
        ]
    )
    relay.release.clear()
    proc = RemoteProcessHandle("laptop", "echo hi", login=True, timeout=30)
    assert proc.poll() is None and proc.returncode is None
    assert proc.wait(timeout=0.05) == UNREACHABLE  # still running: an int, as the Protocol says
    assert not hasattr(proc, "pid")
    relay.release.set()
    assert wait_exit(proc) == 3
    # poll() is non-None only after the write end closed: the drain reads everything, then EOF.
    assert read_to_eof(proc, timeout=1.0).decode("utf-8") == "hello wörld\n"
    assert relay.started == [("laptop", "echo hi", True, 30)]
    assert proc.wait() == 3


def test_exit_is_published_only_after_the_write_end_closed(fake, monkeypatch):
    relay = fake([{"chunks": ["x"], "next": 1, "done": True, "returncode": 0}])
    relay.release.clear()
    seen_at_close = []

    class OsSpy:
        def __getattr__(self, name):
            return getattr(os, name)

        def close(self, fd):
            seen_at_close.append(procs[0].poll())
            os.close(fd)

    procs = []
    monkeypatch.setattr(handle_module, "os", OsSpy())
    procs.append(RemoteProcessHandle("laptop", "true", login=False, timeout=5))
    relay.release.set()
    assert wait_exit(procs[0]) == 0
    assert seen_at_close == [None]


def test_refused_start_says_why_and_returns_255(fake):
    fake([], start_error=client.HandsError("hands: laptop is offline, so nothing ran."))
    proc = RemoteProcessHandle("laptop", "true", login=False, timeout=5)
    assert wait_exit(proc) == 255
    assert read_to_eof(proc) == b"hands: laptop is offline, so nothing ran."


def test_stdin_goes_to_the_relay_beside_the_script(fake):
    relay = fake([{"chunks": [], "next": 0, "done": True, "returncode": 0}])
    proc = RemoteProcessHandle("laptop", "cat > f", login=False, timeout=5, stdin="sudo text\n")
    assert wait_exit(proc) == 0
    assert relay.started == [("laptop", "cat > f", False, 5)]
    assert relay.stdin == "sudo text\n"
    assert relay.file_op is False


def test_file_op_marker_goes_to_the_relay(fake):
    relay = fake([{"chunks": [], "next": 0, "done": True, "returncode": 0}])
    proc = RemoteProcessHandle("laptop", "cat > f", login=False, timeout=5, file_op=True)
    assert wait_exit(proc) == 0
    assert relay.file_op is True


def test_relay_lost_mid_command_keeps_partial_output_and_never_says_nothing_ran(fake):
    """C23: once the job exists the command may be running, so it is cancelled best effort and the
    note says so, instead of the relay-down text that says nothing ran."""
    relay = fake(
        [
            {"chunks": ["partial"], "next": 1, "done": False},
            client.RelayUnavailable(messages.RELAY_DOWN),
        ]
    )
    proc = RemoteProcessHandle("laptop", "make", login=False, timeout=5)
    assert wait_exit(proc) == 255
    output = read_to_eof(proc).decode("utf-8")
    assert output == "partial\n" + messages.contact_lost("laptop")
    assert "nothing ran" not in output
    assert relay.cancelled == ["job1"]


def test_relay_failure_without_returncode_is_255_with_reason(fake):
    fake([{"chunks": ["a"], "next": 1, "done": True, "error": "hands: laptop went offline"}])
    proc = RemoteProcessHandle("laptop", "make", login=False, timeout=5)
    assert wait_exit(proc) == 255
    assert read_to_eof(proc) == b"a\nhands: laptop went offline"


@pytest.mark.parametrize(
    ("error", "returncode", "expected"),
    [
        (
            "stopped_by_person",
            130,
            "The person at laptop stopped the session. Nothing else will run. "
            "Do not guess a reason or retry.",
        ),
        (
            "session_timeout",
            124,
            "The 30 minute session on laptop ended. Nothing else will run. "
            "Do not guess a reason or retry.",
        ),
        (
            "unknown_job_type",
            126,
            "The device rejected this job type. Nothing ran. Do not guess a reason or retry.",
        ),
    ],
)
@pytest.mark.parametrize(
    ("script", "file_op"),
    [("echo terminal", False), ("cat report.txt", True), ("sleep 30 &", False)],
    ids=["terminal", "file", "background"],
)
def test_device_result_codes_are_plain_for_remote_outputs(
    fake, error, returncode, expected, script, file_op
):
    relay = fake(
        [
            {
                "chunks": [],
                "next": 0,
                "done": True,
                "returncode": returncode,
                "error": error,
            }
        ]
    )
    proc = RemoteProcessHandle("laptop", script, login=False, timeout=5, file_op=file_op)

    assert read_to_eof(proc).decode("utf-8") == expected
    assert wait_exit(proc) == returncode
    assert relay.file_op is file_op


def test_kill_cancels_at_the_relay_and_drops_later_output(fake):
    relay = fake([{"chunks": ["too late"], "next": 1, "done": True, "returncode": 137}])
    relay.release.clear()
    proc = RemoteProcessHandle("laptop", "sleep 99", login=False, timeout=5)
    deadline = time.monotonic() + 5
    while proc._job_id is None:
        assert time.monotonic() < deadline
        time.sleep(0.005)
    proc.kill()
    proc.kill()
    assert relay.cancelled == ["job1"]
    relay.release.set()
    assert wait_exit(proc) == 137
    assert read_to_eof(proc) == b""


def test_kill_before_the_job_exists_cancels_it_once_queued(fake, monkeypatch):
    queued = threading.Event()
    relay = fake([{"chunks": [], "next": 0, "done": True, "returncode": 137}])
    original = relay.start_job

    def slow_start(device, **kwargs):
        queued.wait(5)
        return original(device, **kwargs)

    monkeypatch.setattr(client, "start_job", slow_start)
    proc = RemoteProcessHandle("laptop", "sleep 99", login=False, timeout=5)
    proc.kill()
    assert relay.cancelled == []
    queued.set()
    wait_exit(proc)
    assert relay.cancelled == ["job1"]


def test_closed_reader_does_not_break_the_worker(fake):
    relay = fake([{"chunks": ["x" * 200_000], "next": 1, "done": True, "returncode": 0}])
    relay.release.clear()
    proc = RemoteProcessHandle("laptop", "yes", login=False, timeout=5)
    proc.stdout.close()
    relay.release.set()
    assert wait_exit(proc) == 0


def test_inline_limit_keeps_head_and_tail_around_a_note(fake):
    fake(
        [
            {"chunks": ["a" * 6000, "b" * 6000], "next": 2, "done": False},
            {"chunks": ["c" * 6000], "next": 3, "done": True, "returncode": 0},
        ]
    )
    proc = RemoteProcessHandle("laptop", "yes", login=False, timeout=5, inline_limit=8192)
    output = read_to_eof(proc, timeout=5).decode("utf-8")  # read as core's drain does: concurrently
    assert wait_exit(proc) == 0
    note = messages.output_omitted(18000 - 8192, "job1")
    assert output == "a" * 4096 + f"\n{note}\n" + "c" * 4096


def test_inline_limit_has_a_floor_and_leaves_short_output_alone(fake):
    fake([{"chunks": ["x" * 8000], "next": 1, "done": True, "returncode": 0}])
    proc = RemoteProcessHandle("laptop", "yes", login=False, timeout=5, inline_limit=10)
    assert read_to_eof(proc, timeout=5) == b"x" * 8000  # under the floor of handle.MIN_INLINE_LIMIT
    assert wait_exit(proc) == 0


def test_inline_limit_tail_comes_before_a_relay_notice(fake):
    fake(
        [
            {"chunks": ["a" * 9000], "next": 1, "done": False},
            client.HandsError(messages.RELAY_LOST),
        ]
    )
    proc = RemoteProcessHandle("laptop", "yes", login=False, timeout=5, inline_limit=8192)
    output = read_to_eof(proc, timeout=5).decode("utf-8")
    assert wait_exit(proc) == 255
    assert output.endswith("a" * 4096 + "\n" + messages.contact_lost("laptop"))
    assert messages.output_omitted(9000 - 8192, "job1") in output
