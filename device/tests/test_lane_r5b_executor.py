import builtins
import io
import json
from types import SimpleNamespace
from unittest.mock import Mock

import psutil
import pytest

from hermeshands_device import executor


def _stat(pid, ticks, name="sleep"):
    return f"{pid} ({name}) S " + " ".join(["0"] * 18) + f" {ticks} 0 0\n"


def _run_guardian(lines, identities, *, platform="darwin", groups=None, sessions=None, clock=None, at_eof=None, at_line=None, stat_files=None):
    killed = []
    groups = groups if groups is not None else {}
    sessions = sessions if sessions is not None else {}
    clock = clock if clock is not None else [100.0]

    def process(pid):
        if pid not in identities:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(pid=pid, create_time=lambda: identities[pid])

    def getpgid(pid):
        if pid not in identities:
            raise ProcessLookupError(pid)
        return groups.get(pid, 100)

    def getsid(pid):
        if pid not in identities:
            raise ProcessLookupError(pid)
        return sessions.get(pid, 100)

    class Input(io.StringIO):
        def readline(self):
            line = super().readline()
            if line and at_line:
                at_line(line)
            if not line and at_eof:
                at_eof()
            return line

    incoming = Input("".join(lines))
    outgoing = io.StringIO()

    def fake_open(path, mode="r", *args, **kwargs):
        pid = int(str(path).split("/")[2])
        if pid not in stat_files:
            raise FileNotFoundError(path)
        return io.BytesIO(stat_files[pid].encode())

    modules = {
        "os": SimpleNamespace(getpgid=getpgid, getsid=getsid, killpg=lambda *args: killed.append(args)),
        "signal": SimpleNamespace(SIGINT=2, SIGHUP=1, SIGKILL=9, SIG_IGN=1, signal=lambda *args: None),
        "sys": SimpleNamespace(stdin=incoming, stdout=outgoing, platform=platform),
        "select": SimpleNamespace(select=lambda *args: ([incoming], [], [])),
        "time": SimpleNamespace(monotonic=lambda: clock[0]),
        "psutil": SimpleNamespace(Process=process, process_iter=lambda: [process(pid) for pid in list(identities)], pid_exists=lambda pid: pid in identities, Error=psutil.Error),
    }
    actual_import = builtins.__import__

    def imports(name, *args, **kwargs):
        return modules[name] if name in modules else actual_import(name, *args, **kwargs)

    namespace = {"__builtins__": {**vars(builtins), "__import__": imports, "open": fake_open, "print": lambda value, **kwargs: outgoing.write(value + "\n")}}
    exec(executor._POSIX_GUARDIAN_CODE, namespace)
    return outgoing.getvalue(), killed


@pytest.mark.parametrize("case", ["late_child", "foreign_leader", "stale", "other_session", "other_group"])
def test_guardian_keeps_a_group_whose_recorded_members_exited_after_starting_a_late_child(case):
    identities = {100: 1.0, 101: 2.0}
    groups = {}
    sessions = {}
    clock = [100.0]

    def late_fork():
        identities.pop(100)
        identities.pop(101)
        identities[102] = 3.0
        if case == "foreign_leader":
            identities[100] = 9.0
        elif case == "stale":
            clock[0] += executor._POSIX_CONTINUITY_WINDOW + 0.5
        elif case == "other_session":
            sessions[102] = 555
        elif case == "other_group":
            groups[102] = 555

    _, killed = _run_guardian(['set 100 1.0 {"100":1.0,"101":2.0}\n'], identities, groups=groups, sessions=sessions, clock=clock, at_eof=late_fork)
    assert killed == ([(100, 9)] if case == "late_child" else [])


def test_guardian_check_rescans_and_records_late_members_with_their_own_identity():
    identities = {100: 1.0, 101: 2.0}

    def late_fork(line):
        if line.startswith("check"):
            identities.pop(100)
            identities.pop(101)
            identities[102] = 3.0

    output, killed = _run_guardian(['add 100 1.0 {"100":1.0,"101":2.0}\n', "check 100\n"], identities, at_line=late_fork)
    assert output.splitlines()[-1] == 'ack {"102": 3.0}'
    assert killed == [(100, 9)]


def test_a_new_registration_does_not_inherit_continuity_from_an_older_group():
    identities = {100: 1.0, 101: 2.0}

    def replaced(line):
        if line.startswith("add"):
            identities.pop(100)
            identities.pop(101)
            identities[102] = 3.0

    output, _ = _run_guardian(['set 100 1.0 {"100":1.0,"101":2.0}\n', 'add 100 5.0 {"100":5.0}\n'], identities, at_line=replaced)
    assert output.splitlines()[-1] == "ack {}"


@pytest.mark.parametrize("ticks", [4242, 4243])
def test_guardian_identity_on_linux_is_start_ticks_not_the_wall_clock(ticks):
    stat_files = {100: _stat(100, ticks, "we) ird (name")}
    output, killed = _run_guardian(['add 100 4242.0 {"100":4242.0}\n'], {100: 1.0}, platform="linux", stat_files=stat_files)
    if ticks == 4242:
        assert output.splitlines()[1] == 'ack {"100": 4242.0}'
        assert killed == [(100, 9)]
    else:
        assert output.splitlines()[1] == "ack {}"
        assert killed == []


def _parent_linux(monkeypatch, stat_files):
    def fake_open(path, mode="r", *args, **kwargs):
        pid = int(str(path).split("/")[2])
        if pid not in stat_files:
            raise FileNotFoundError(path)
        return io.BytesIO(stat_files[pid].encode())

    def drifting(pid):
        if pid not in stat_files:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(pid=pid, create_time=Mock(side_effect=AssertionError("the wall clock create_time was used on Linux")))

    monkeypatch.setattr(executor, "_LINUX", True, raising=False)
    monkeypatch.setattr(executor, "open", fake_open, raising=False)
    monkeypatch.setattr(executor.psutil, "Process", drifting)
    monkeypatch.setattr(executor.psutil, "process_iter", lambda: [SimpleNamespace(pid=pid) for pid in stat_files])
    monkeypatch.setattr(executor.os, "getpgid", lambda pid: 100, raising=False)


def test_parent_reads_start_ticks_after_the_last_parenthesis(monkeypatch):
    _parent_linux(monkeypatch, {100: _stat(100, 4242, "a) b (c) d")})
    assert executor._start_time(100) == 4242.0


def test_parent_group_check_uses_start_ticks_on_linux(monkeypatch):
    _parent_linux(monkeypatch, {100: _stat(100, 4242), 101: _stat(101, 4300, "x) (y")})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {})
    assert executor._posix_group_is_ours(100, 4242.0)
    assert executor._POSIX_MEMBERS[100] == {100: 4242.0, 101: 4300.0}
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {})
    assert not executor._posix_group_is_ours(100, 4242.005)


def test_recorded_reap_on_linux_uses_start_ticks(monkeypatch):
    killed = []
    _parent_linux(monkeypatch, {1234: _stat(1234, 4242)})
    monkeypatch.setattr(executor.os, "killpg", lambda pid, sig: killed.append(pid), raising=False)
    monkeypatch.setattr(executor.os, "name", "posix")
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    executor.terminate_recorded(1234, 4243.0)
    assert killed == []
    executor.terminate_recorded(1234, 4242.0)
    assert killed == [1234]


@pytest.mark.parametrize("recorded_boot", ["boot-a", "boot-b", None])
def test_reap_on_linux_skips_records_from_another_boot(monkeypatch, tmp_path, recorded_boot):
    monkeypatch.setattr(executor.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(executor, "_LINUX", True, raising=False)
    killed = []
    monkeypatch.setattr(executor, "terminate_recorded", lambda pid, created: killed.append((pid, created)))
    monkeypatch.setattr(executor, "_boot_id", lambda: recorded_boot, raising=False)
    executor.record_process("old-job", 1234, 4242.0)
    monkeypatch.setattr(executor, "_boot_id", lambda: "boot-a", raising=False)
    executor.reap_recorded_processes()
    assert killed == ([(1234, 4242.0)] if recorded_boot == "boot-a" else [])
    assert not executor.record_path("old-job").exists()


class _FakeGuardian:
    def __init__(self, identities, refuse=()):
        self.sent = []
        self.responses = ["ready\n"]
        self.returncode = None
        guardian = self

        class Input:
            closed = False

            def write(self, text):
                guardian.sent.append(text.strip())
                parts = text.split()
                members = {}
                if parts[0] in ("add", "set") and int(parts[1]) not in refuse:
                    members = {pid: created for pid, created in json.loads(parts[3]).items() if identities.get(int(pid)) == created}
                guardian.responses.append("ack " + json.dumps(members) + "\n")

            def flush(self):
                pass

            def close(self):
                self.closed = True

        class Output:
            def readline(self):
                return guardian.responses.pop(0) if guardian.responses else ""

            def close(self):
                pass

        self.stdin = Input()
        self.stdout = Output()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        self.returncode = -9


def _respawn(monkeypatch, groups, identities, refuse=()):
    guardian = _FakeGuardian(identities, refuse)
    killed = []
    monkeypatch.setattr(executor, "_LINUX", False, raising=False)
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", None)
    monkeypatch.setattr(executor, "_POSIX_GROUPS", dict(groups))
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {})
    monkeypatch.setattr(executor.subprocess, "Popen", lambda *args, **kwargs: guardian)
    monkeypatch.setattr(executor.select, "select", lambda readers, *args: (readers, [], []))

    def process(pid):
        if pid not in identities:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(pid=pid, create_time=lambda: identities[pid])

    def getpgid(pid):
        if pid not in identities:
            raise ProcessLookupError(pid)
        return pid

    monkeypatch.setattr(executor.psutil, "Process", process)
    monkeypatch.setattr(executor.psutil, "process_iter", lambda: [process(pid) for pid in list(identities)])
    monkeypatch.setattr(executor.os, "getpgid", getpgid, raising=False)
    monkeypatch.setattr(executor.os, "killpg", lambda pgid, sig: killed.append(pgid), raising=False)
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    return guardian, killed


def test_a_respawned_guardian_drops_finished_groups_and_registers_the_new_job(monkeypatch):
    guardian, killed = _respawn(monkeypatch, {100: 1.0, 200: 2.0}, {200: 2.0, 300: 3.0})
    executor._send_to_posix_guardian("add 300 3.0\n")
    assert guardian.sent == ['add 200 2.0 {"200":2.0}', 'add 300 3.0 {"300":3.0}']
    assert executor._POSIX_GROUPS == {200: 2.0}
    assert 100 not in executor._POSIX_MEMBERS
    assert killed == []


def test_a_restored_group_the_new_guardian_cannot_match_is_dropped_not_fatal(monkeypatch):
    guardian, killed = _respawn(monkeypatch, {200: 2.0}, {200: 2.0, 300: 3.0}, refuse={200})
    executor._send_to_posix_guardian("add 300 3.0\n")
    assert executor._POSIX_GROUPS == {}
    assert 200 not in executor._POSIX_MEMBERS
    assert executor._POSIX_GUARDIAN is guardian
    assert killed == []


def test_a_respawn_does_not_restore_the_group_this_call_registers(monkeypatch):
    guardian, _ = _respawn(monkeypatch, {300: 3.0}, {300: 3.0})
    executor._send_to_posix_guardian("add 300 3.0\n")
    assert guardian.sent == ['add 300 3.0 {"300":3.0}']


def test_the_new_jobs_own_registration_still_fails_closed(monkeypatch):
    _, killed = _respawn(monkeypatch, {300: 3.0}, {300: 3.0}, refuse={300})
    with pytest.raises(RuntimeError, match="Could not establish job guardian protection"):
        executor._send_to_posix_guardian("add 300 3.0\n")
    assert executor._POSIX_GUARDIAN is None
    assert killed == [300]


def test_a_guardian_failure_forgets_groups_that_are_not_ours(monkeypatch, caplog):
    killed = []
    guardian = SimpleNamespace(poll=lambda: None, stdin=io.StringIO(), stdout=io.StringIO(), kill=Mock(), wait=Mock())
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", guardian)
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {100: 1.0, 200: 2.0, 300: 3.0})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {200: {200: 2.0}})
    monkeypatch.setattr(executor, "_posix_group_is_ours", lambda pgid, created: pgid == 100)
    monkeypatch.setattr(executor.psutil, "process_iter", lambda: [SimpleNamespace(pid=301)])
    monkeypatch.setattr(executor.os, "getpgid", lambda pid: 300, raising=False)
    monkeypatch.setattr(executor.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(executor.os, "killpg", lambda pgid, sig: killed.append(pgid), raising=False)
    monkeypatch.setattr(executor.select, "select", lambda *args: ([], [], []))
    with pytest.raises(RuntimeError, match="guardian"):
        executor._send_to_posix_guardian("set 100 1.0\n")
    assert killed == [100]
    assert executor._POSIX_GROUPS == {100: 1.0}
    assert executor._POSIX_MEMBERS == {}
    warnings = [record.getMessage() for record in caplog.records]
    assert any("300" in message and "cannot prove" in message for message in warnings), warnings
    assert not any("200" in message and "cannot prove" in message for message in warnings), warnings
