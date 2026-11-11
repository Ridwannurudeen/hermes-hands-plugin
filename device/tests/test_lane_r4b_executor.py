import builtins
import io
from types import SimpleNamespace
from unittest.mock import Mock

import psutil
import pytest

from hermeshands_device import executor


def _fake_group(monkeypatch, identities, statuses=None):
    monkeypatch.setattr(executor, "_LINUX", False)
    statuses = statuses or {}

    def process(pid):
        if pid not in identities:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(pid=pid, create_time=lambda: identities[pid], status=lambda: statuses.get(pid, psutil.STATUS_SLEEPING))

    monkeypatch.setattr(executor.psutil, "Process", process)
    monkeypatch.setattr(executor.psutil, "process_iter", lambda: [process(pid) for pid in identities])
    monkeypatch.setattr(executor.os, "getpgid", lambda pid: 100, raising=False)


def test_an_exited_leader_is_seen_without_being_reaped(monkeypatch):
    monkeypatch.setattr(executor.os, "name", "posix")
    _fake_group(monkeypatch, {100: 1.0}, {100: psutil.STATUS_ZOMBIE})
    proc = SimpleNamespace(pid=100, returncode=None, poll=Mock(side_effect=AssertionError("reaped the leader")))
    assert not executor._leader_running(proc, 1.0)
    _fake_group(monkeypatch, {100: 1.0})
    assert executor._leader_running(proc, 1.0)
    _fake_group(monkeypatch, {100: 3.0})
    assert executor._leader_running(proc, 1.0), "a wall clock step made a running leader look finished"
    _fake_group(monkeypatch, {})
    assert not executor._leader_running(proc, 1.0)
    proc.poll.assert_not_called()


def test_the_group_is_recorded_before_reaping_and_keeps_its_background_child(monkeypatch):
    sent = []
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {100: 1.0})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {100: {100: 1.0}})
    monkeypatch.setattr(executor, "_send_to_posix_guardian", lambda line, deadline=None: sent.append(line))
    identities = {100: 1.0, 101: 2.0}
    _fake_group(monkeypatch, identities, {100: psutil.STATUS_ZOMBIE})
    executor._record_posix_group_at_exit(100, 1.0)
    assert executor._POSIX_MEMBERS[100] == {100: 1.0, 101: 2.0}
    assert sent == ["set 100 1.0\n"]
    identities.pop(100)
    assert executor._posix_group_is_ours(100, 1.0)


@pytest.mark.parametrize("case", ["leader_not_held", "untracked", "no_children"])
def test_recording_at_exit_keeps_the_ownership_checks(monkeypatch, case):
    sent = []
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {} if case == "untracked" else {100: 1.0})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {})
    monkeypatch.setattr(executor, "_send_to_posix_guardian", lambda line, deadline=None: sent.append(line))
    identities = {100: 1.0}
    if case != "no_children":
        identities[101] = 10.0
    _fake_group(monkeypatch, identities, {} if case == "leader_not_held" else {100: psutil.STATUS_ZOMBIE})
    executor._record_posix_group_at_exit(100, 1.0)
    assert sent == []
    assert executor._POSIX_MEMBERS == ({100: {100: 1.0}} if case == "no_children" else {})


def test_a_guardian_failure_at_exit_does_not_fail_the_command(monkeypatch):
    monkeypatch.setattr(executor, "_POSIX_GROUPS", {100: 1.0})
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {})
    monkeypatch.setattr(executor, "_send_to_posix_guardian", Mock(side_effect=RuntimeError("Could not establish job guardian protection")))
    _fake_group(monkeypatch, {100: 1.0, 101: 2.0}, {100: psutil.STATUS_ZOMBIE})
    executor._record_posix_group_at_exit(100, 1.0)
    assert executor._POSIX_MEMBERS[100] == {100: 1.0, 101: 2.0}


def test_an_empty_set_ack_is_not_a_registration_failure(monkeypatch):
    guardian = SimpleNamespace(poll=lambda: None, stdin=io.StringIO(), stdout=io.StringIO("ack {}\n"))
    monkeypatch.setattr(executor, "_POSIX_GUARDIAN", guardian)
    monkeypatch.setattr(executor, "_POSIX_MEMBERS", {100: {100: 1.0, 101: 2.0}})
    monkeypatch.setattr(executor.select, "select", lambda *args: ([guardian.stdout], [], []))
    executor._send_to_posix_guardian("set 100 1.0\n")
    assert guardian.stdin.getvalue() == 'set 100 1.0 {"100":1.0,"101":2.0}\n'
    assert executor._POSIX_MEMBERS[100] == {}


def test_guardian_program_adopts_the_set_members_and_kills_them_after_parent_eof():
    killed = []
    identities = {101: 2.0}

    def process(pid):
        if pid not in identities:
            raise psutil.NoSuchProcess(pid)
        return SimpleNamespace(pid=pid, create_time=lambda: identities[pid])

    incoming = io.StringIO('set 100 1.0 {"100":1.0,"101":2.0}\n')
    outgoing = io.StringIO()
    modules = {
        "os": SimpleNamespace(getpgid=lambda pid: 100, killpg=lambda *args: killed.append(args)),
        "signal": SimpleNamespace(SIGINT=2, SIGHUP=1, SIGKILL=9, SIG_IGN=1, signal=lambda *args: None),
        "sys": SimpleNamespace(stdin=incoming, stdout=outgoing, platform="darwin"),
        "select": SimpleNamespace(select=lambda *args: ([incoming], [], [])),
        "psutil": SimpleNamespace(Process=process, process_iter=lambda: [process(pid) for pid in identities], Error=psutil.Error),
    }
    actual_import = builtins.__import__

    def imports(name, *args, **kwargs):
        return modules[name] if name in modules else actual_import(name, *args, **kwargs)

    namespace = {"__builtins__": {**vars(builtins), "__import__": imports, "print": lambda value, **kwargs: outgoing.write(value + "\n")}}
    exec(executor._POSIX_GUARDIAN_CODE, namespace)
    assert outgoing.getvalue() == 'ready\nack {"101": 2.0}\n'
    assert killed == [(100, 9)]
