import builtins
import io
import json
from types import SimpleNamespace

import psutil
import pytest

from hermeshands_device import executor


class _StalledGuardian:
    def __init__(self, events):
        self.events = events

        class Input:
            def write(self, text):
                events.append(("write", text.strip()))

            def flush(self):
                pass

            def close(self):
                events.append(("close", None))

        class Output:
            def readline(self):
                return ""

            def close(self):
                pass

        self.stdin = Input()
        self.stdout = Output()
        self.returncode = None

    def poll(self):
        return self.returncode

    def kill(self):
        self.events.append(("kill", None))
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def test_a_stalled_check_of_old_groups_fails_only_the_new_job(monkeypatch):
    events = []
    killed = []
    guardian = _StalledGuardian(events)
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", guardian)
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {100: 1.0, 200: 2.0})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {100: {100: 1.0}, 200: {200: 2.0}})
    monkeypatch.setattr(executor, "_posix_group_is_ours", lambda *args, **kwargs: True)
    monkeypatch.setattr(executor.select, "select", lambda *args: ([], [], []))
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor.os, "killpg", lambda pgid, sig: killed.append(pgid), raising=False)
    with pytest.raises(RuntimeError, match="Could not establish job guardian protection"):
        executor._track_posix_group(300, 3.0)
    assert killed == []
    assert executor._POSIX_GROUPS == {100: 1.0, 200: 2.0}
    assert executor._POSIX_GUARDIAN is None
    kinds = [kind for kind, _ in events]
    assert "kill" in kinds
    assert "close" not in kinds[: kinds.index("kill")], (
        "closing input first makes the guardian kill every group"
    )


def test_a_dead_guardian_during_the_check_still_fails_closed(monkeypatch):
    killed = []
    guardian = _StalledGuardian([])
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", guardian)
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {100: 1.0})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {100: {100: 1.0}})
    monkeypatch.setattr(executor, "_posix_group_is_ours", lambda *args, **kwargs: True)
    monkeypatch.setattr(executor.select, "select", lambda readers, *args: (readers, [], []))
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor.os, "killpg", lambda pgid, sig: killed.append(pgid), raising=False)
    with pytest.raises(RuntimeError, match="Could not establish job guardian protection"):
        executor._track_posix_group(300, 3.0)
    assert killed == [100]


def test_a_new_guardian_that_never_starts_still_fails_closed(monkeypatch):
    killed = []
    events = []
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", None)
    monkeypatch.setattr(executor.subprocess, "Popen", lambda *args, **kwargs: _StalledGuardian(events))
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {100: 1.0})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {100: {100: 1.0}})
    monkeypatch.setattr(executor, "_posix_group_is_ours", lambda *args, **kwargs: True)
    monkeypatch.setattr(executor.select, "select", lambda *args: ([], [], []))
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor.os, "killpg", lambda pgid, sig: killed.append(pgid), raising=False)
    with pytest.raises(RuntimeError, match="Could not establish job guardian protection"):
        executor._send_to_posix_guardian("")
    assert killed == [100]


def test_tracking_checks_every_old_group_in_one_guardian_line(monkeypatch):
    sent = []
    scans = []
    identities = {pgid: float(pgid) for pgid in range(100, 120)}
    identities[300] = 3.0
    monkeypatch.setattr(executor, "_LINUX", False)
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {pgid: float(pgid) for pgid in range(100, 120)})
    monkeypatch.setattr(
        executor, "_POSIX_MEMBERS", {pgid: {pgid: float(pgid)} for pgid in range(100, 120)}
    )
    monkeypatch.setattr(
        executor, "_send_to_posix_guardian", lambda line, deadline=None: sent.append(line)
    )
    monkeypatch.setattr(
        executor.psutil,
        "Process",
        lambda pid: SimpleNamespace(pid=pid, create_time=lambda: identities[pid]),
    )
    monkeypatch.setattr(
        executor.psutil,
        "process_iter",
        lambda: scans.append(1) or [SimpleNamespace(pid=pid) for pid in identities],
    )
    monkeypatch.setattr(executor.os, "getpgid", lambda pid: pid, raising=False)
    executor._track_posix_group(300, 3.0)
    assert sent == ["checkall 0\n", "add 300 3.0\n"]
    assert len(scans) == 1
    assert len(executor._POSIX_GROUPS) == 21


def _run_guardian(lines, identities, scans, at_line=None):
    def process(pid):
        if pid not in identities:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(pid=pid, create_time=lambda: identities[pid])

    def getpgid(pid):
        if pid not in identities:
            raise ProcessLookupError(pid)
        return pid - pid % 10

    class Input(io.StringIO):
        def readline(self):
            line = super().readline()
            if line and at_line:
                at_line(line)
            return line

    incoming = Input("".join(lines))
    outgoing = io.StringIO()
    modules = {
        "os": SimpleNamespace(getpgid=getpgid, getsid=getpgid, killpg=lambda *args: None),
        "signal": SimpleNamespace(
            SIGINT=2, SIGHUP=1, SIGKILL=9, SIG_IGN=1, signal=lambda *args: None
        ),
        "sys": SimpleNamespace(stdin=incoming, stdout=outgoing, platform="darwin"),
        "select": SimpleNamespace(select=lambda *args: ([incoming], [], [])),
        "time": SimpleNamespace(monotonic=lambda: 100.0),
        "psutil": SimpleNamespace(
            Process=process,
            process_iter=lambda: scans.append(1) or [process(pid) for pid in list(identities)],
            pid_exists=lambda pid: pid in identities,
            Error=psutil.Error,
        ),
    }
    actual_import = builtins.__import__

    def imports(name, *args, **kwargs):
        return modules[name] if name in modules else actual_import(name, *args, **kwargs)

    namespace = {
        "__builtins__": {
            **vars(builtins),
            "__import__": imports,
            "print": lambda value, **kwargs: outgoing.write(value + "\n"),
        }
    }
    exec(executor._POSIX_GUARDIAN_CODE, namespace)
    return outgoing.getvalue()


def test_guardian_scans_processes_once_per_line_not_once_per_group():
    identities = {}
    for group in range(20):
        identities[1000 + group * 10] = float(group)
        identities[1001 + group * 10] = float(group) + 0.5
    lines = [f"add {1000 + group * 10} {float(group)!r}\n" for group in range(20)] + [
        "checkall 0\n"
    ]
    scans = []
    during_check = []

    def mark(line):
        if line.startswith("checkall"):
            identities[1002] = 9.0
            during_check.append(len(scans))

    output = _run_guardian(lines, identities, scans, at_line=mark)
    answer = json.loads(output.splitlines()[-1].split(" ", 1)[1])
    assert len(answer) == 20
    assert answer["1000"] == {"1000": 0.0, "1001": 0.5, "1002": 9.0}
    assert len(scans) - during_check[0] <= 2, "checkall must use one scan for every group"
    assert len(scans) <= 23, "the guardian rescans every group for every input line"
