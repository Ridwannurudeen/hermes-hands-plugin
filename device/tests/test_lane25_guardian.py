import builtins
import io
from types import SimpleNamespace

import psutil
import pytest

from hermeshands_device import executor


def _run_guardian(*, platform, ending, identity, action="set"):
    killed = []
    identities = {100: 9.0 if identity == "unverified" else 1.0, 200: 2.0}
    groups = {100: 100, 200: 200}
    acknowledgements = []

    def process(pid):
        return SimpleNamespace(pid=pid, create_time=lambda: identities[pid])

    def stat(path, mode):
        pid = int(path.split("/")[2])
        return io.BytesIO((f"{pid} (sleep) S " + "0 " * 18 + f"{identities[pid]} 0\n").encode())

    def output(value, **kwargs):
        if not value.startswith("ack "):
            return
        acknowledgements.append(value)
        if len(acknowledgements) != 2:
            return
        if identity == "reused":
            identities[100] = 9.0
        elif identity == "moved":
            groups[100] = 999
        if ending == "broken_ack":
            raise BrokenPipeError("agent closed acknowledgement pipe")

    incoming = io.StringIO(f"add 200 2.0\n{action} 100 1.0\n" + ("invalid\n" if ending == "invalid_line" else ""))
    modules = {
        "os": SimpleNamespace(getpgid=lambda pid: groups[pid], getsid=lambda pid: groups[pid], killpg=lambda *args: killed.append(args)),
        "signal": SimpleNamespace(SIGINT=2, SIGHUP=1, SIGKILL=9, SIG_IGN=1, signal=lambda *args: None),
        "sys": SimpleNamespace(stdin=incoming, platform=platform),
        "select": SimpleNamespace(select=lambda *args: ([incoming], [], [])),
        "time": SimpleNamespace(monotonic=lambda: 100.0),
        "psutil": SimpleNamespace(Process=process, process_iter=lambda: [process(pid) for pid in identities], pid_exists=lambda pid: pid in identities, Error=psutil.Error),
    }
    actual_import = builtins.__import__

    def imports(name, *args, **kwargs):
        return modules[name] if name in modules else actual_import(name, *args, **kwargs)

    namespace = {"__builtins__": {**vars(builtins), "__import__": imports, "open": stat, "print": output}}
    if ending == "eof":
        exec(executor._POSIX_GUARDIAN_CODE, namespace)
    else:
        error, message = (BrokenPipeError, "agent closed acknowledgement pipe") if ending == "broken_ack" else (ValueError, "not enough values to unpack")
        with pytest.raises(error, match=message):
            exec(executor._POSIX_GUARDIAN_CODE, namespace)
    assert len(acknowledgements) == 2
    return killed


@pytest.mark.parametrize("platform", ["linux", "darwin"])
@pytest.mark.parametrize("action", ["add", "set"])
def test_broken_acknowledgement_still_kills_verified_groups(platform, action):
    assert _run_guardian(platform=platform, ending="broken_ack", identity="verified", action=action) == [(200, 9), (100, 9)]


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_ordinary_eof_still_kills_verified_groups(platform):
    assert _run_guardian(platform=platform, ending="eof", identity="verified") == [(200, 9), (100, 9)]


@pytest.mark.parametrize("platform", ["linux", "darwin"])
@pytest.mark.parametrize("identity", ["unverified", "reused", "moved"])
@pytest.mark.parametrize("ending", ["broken_ack", "invalid_line"])
def test_errors_recheck_identity_and_skip_unsafe_groups(platform, identity, ending):
    assert _run_guardian(platform=platform, ending=ending, identity=identity) == [(200, 9)]
