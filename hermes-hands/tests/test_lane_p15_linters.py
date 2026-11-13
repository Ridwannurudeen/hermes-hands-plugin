"""External lint commands stay bound to the approved write destination."""

import json
import os
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("tools.file_operations")

from hands import environment, messages  # noqa: E402
from hands_fakes import device_bindir, hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401


LINTERS = [
    (".js", "node", "--check"),
    (".ts", "npx", "tsc --noEmit"),
    (".go", "go", "vet"),
    (".rs", "rustfmt", "--check"),
]


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("extension,binary,flags", LINTERS)
@pytest.mark.parametrize("path", ["/c/approved/check", "/approved/a spaced 'check'", "C:/approved/check"])
def test_lint_templates_equal_the_real_core(monkeypatch, windows, extension, binary, flags, path):
    from tools.environments import local
    from tools.file_operations import ShellFileOperations
    from tools.file_operations_common import ExecuteResult

    path += extension
    monkeypatch.setattr(local, "_IS_WINDOWS", windows)
    monkeypatch.setattr(environment, "os", SimpleNamespace(**{**vars(os), "name": "nt" if windows else "posix"}))
    ops = ShellFileOperations(SimpleNamespace(cwd="/approved", uses_host_filesystem=False, is_local=False))
    monkeypatch.setattr(ops, "_has_command", lambda name: name == binary)
    captured = []

    def execute(command, **kwargs):
        captured.append((command, kwargs))
        return ExecuteResult(stdout="", exit_code=0)

    monkeypatch.setattr(ops, "_exec", execute)
    assert ops._check_lint(path).success
    assert captured == [(f"{binary} {flags} {ops._escape_native_tool_arg(path)} 2>&1", {"timeout": 30})]
    command = captured[0][0]
    assert (command in environment._file_candidates("write_file", {}, path, command)) is (not windows)
    assert command not in environment._file_candidates("write_file", {}, path + ".other", command)
    assert command + "; touch unapproved" not in environment._file_candidates("write_file", {}, path, command)


@pytest.mark.parametrize("gateway_windows,device_windows", [(False, False), (False, True), (True, False), (True, True)])
@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("extension,binary,flags", LINTERS)
@pytest.mark.parametrize("mutation", [None, "destination", "flags", "append"])
def test_registered_core_linter_reaches_only_the_approved_destination(
    dispatch, device_bindir, monkeypatch, tool, extension, binary, flags, mutation, gateway_windows, device_windows,
):
    from tools import file_tools
    from tools.environments import local
    from hands import store

    d = dispatch
    device = store.get_device("laptop")
    monkeypatch.setattr(store, "get_device", lambda name: {**device, "os": "Windows" if device_windows else "Linux"})
    monkeypatch.setattr(local, "_IS_WINDOWS", gateway_windows)
    monkeypatch.setattr(environment, "os", SimpleNamespace(**{**vars(os), "name": "nt" if gateway_windows else "posix"}))
    bindir = device_bindir
    trace = d.home / "lint-arguments.txt"
    executable = bindir / binary
    executable.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shlex.quote(f"{d.base}/lint-arguments.txt") + "\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    path = d.home / "work" / ("check" + extension)
    path.write_bytes(b"public\n")
    args = {"path": f"{d.base}/work/check{extension}", **(
        {"content": "approved\n"} if tool == "write_file" else {"old_string": "public", "new_string": "approved"}
    )}
    original = environment.HandsEnvironment.execute
    captured, refused = [], []

    def observe(env, command, cwd="", **kwargs):
        if command.startswith(f"{binary} {flags} "):
            captured.append((command, cwd, dict(kwargs)))
            if mutation == "destination":
                command = command.replace("check" + extension, "other" + extension)
            elif mutation == "flags":
                command = command.replace(flags, flags + " --unapproved", 1)
            elif mutation == "append":
                command += "; touch unapproved"
            result = original(env, command, cwd, **kwargs)
            refused.append(result)
            return result
        return original(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", observe)
    result = d.call(tool, args)
    assert path.read_bytes() == b"approved\n", (result, d.outputs)
    assert captured and all(item[2] == {"timeout": 30} for item in captured), (result, d.outputs)
    command = captured[0][0]
    ops = file_tools._get_file_ops("p8")
    assert command == f"{binary} {flags} {ops._escape_native_tool_arg(args['path'])} 2>&1"
    jobs = [job for job in d.jobs if f"{binary} {flags} " in job["script"]]
    if mutation is None and not gateway_windows:
        assert not json.loads(result).get("error"), result
        mapped = f"{binary} {flags} {environment._quoted(str(path).replace(chr(92), chr(47)) if device_windows else args['path'])} 2>&1"
        if device_windows and os.name != "nt":
            mapped = f'{binary} {flags} "$(cygpath -m {shlex.quote(args["path"])})" 2>&1'
        assert jobs and all(mapped.replace("'", "'\\''") in job["script"] for job in jobs)
        assert all(job["timeout"] == 30 for job in jobs)
        assert trace.read_text(encoding="utf-8").splitlines() == [*flags.split(), str(path).replace("\\", "/") if device_windows else args["path"]]
        assert all(item["returncode"] == 0 for item in refused), refused
    else:
        assert jobs == [] and not trace.exists()
        assert refused and all(item["output"] == messages.WITNESS_CALL_CHANGED for item in refused)
    assert not (d.home / "unapproved").exists()


@pytest.mark.parametrize("device_windows", [False, True])
@pytest.mark.parametrize("root", ["/approved", "/mnt/c/approved", "/cygdrive/c/approved"])
@pytest.mark.parametrize("extension,binary,flags", LINTERS)
def test_linter_refuses_an_unproven_windows_native_destination(
    dispatch, device_bindir, monkeypatch, device_windows, root, extension, binary, flags,
):
    from hands import store
    from tools.environments import local
    import test_lane_p8_findings
    from test_environment import bash_job

    d = dispatch
    device = store.get_device("laptop")
    monkeypatch.setattr(store, "get_device", lambda name: {**device, "os": "Windows" if device_windows else "Linux"})
    monkeypatch.setattr(local, "_IS_WINDOWS", False)
    monkeypatch.setattr(environment, "os", SimpleNamespace(**{**vars(os), "name": "posix"}))
    bindir = device_bindir
    trace = d.home / "lint-arguments.txt"
    (bindir / binary).write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shlex.quote(f"{d.base}/lint-arguments.txt") + "\n", encoding="utf-8",
    )
    (bindir / binary).chmod(0o755)
    monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: bash_job({
        **job, "script": job["script"].replace(root, d.base),
    }))
    args = {"path": f"{root}/work/check{extension}", "content": "approved\n"}
    original = environment.HandsEnvironment.execute

    def change_destination(env, command, cwd="", **kwargs):
        if device_windows and command.startswith(f"{binary} {flags} "):
            command = command.replace("check" + extension, "other" + extension)
        return original(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", change_destination)
    result = d.call("write_file", args)
    assert (d.home / "work" / ("check" + extension)).read_bytes() == b"approved\n", (result, d.outputs)
    jobs = [job for job in d.jobs if f"{binary} {flags} " in job["script"]]
    if device_windows:
        assert jobs == [] and not trace.exists(), (result, d.outputs)
    else:
        expected = f"{binary} {flags} {environment._quoted(args['path'])} 2>&1"
        assert jobs and all(expected.replace("'", "'\\''") in job["script"] for job in jobs)
        assert trace.read_text(encoding="utf-8").splitlines() == [*flags.split(), f"{d.base}/work/check{extension}"]


@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("extension,binary,flags", LINTERS)
@pytest.mark.parametrize("mutation", [None, "destination", "flags", "append"])
def test_windows_tmp_linter_uses_the_exact_approved_destination(
    dispatch, device_bindir, monkeypatch, tool, extension, binary, flags, mutation,
):
    from hands import store
    from tools.environments import local
    import test_lane_p8_findings
    from test_environment import bash_job

    d = dispatch
    device = store.get_device("laptop")
    monkeypatch.setattr(store, "get_device", lambda name: {**device, "os": "Windows"})
    monkeypatch.setattr(local, "_IS_WINDOWS", False)
    monkeypatch.setattr(environment, "os", SimpleNamespace(**{**vars(os), "name": "posix"}))
    bindir = device_bindir
    trace = d.home / "lint-arguments.txt"
    executable = bindir / binary
    executable.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shlex.quote(f"{d.base}/lint-arguments.txt") + "\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    root = "/tmp/hands-approved"
    monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: bash_job({
        **job, "script": job["script"].replace(root, d.base),
    }))
    path = d.home / "work" / ("check" + extension)
    path.write_bytes(b"public\n")
    args = {"path": f"{root}/work/check{extension}", **(
        {"content": "approved\n"} if tool == "write_file" else {"old_string": "public", "new_string": "approved"}
    )}
    original = environment.HandsEnvironment.execute
    refused = []

    def observe(env, command, cwd="", **kwargs):
        if command.startswith(f"{binary} {flags} "):
            if mutation == "destination":
                command = command.replace("check" + extension, "other" + extension)
            elif mutation == "flags":
                command = command.replace(flags, flags + " --unapproved", 1)
            elif mutation == "append":
                command += "; touch unapproved"
            result = original(env, command, cwd, **kwargs)
            refused.append(result)
            return result
        return original(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", observe)
    result = d.call(tool, args)
    assert path.read_bytes() == b"approved\n", (result, d.outputs)
    jobs = [job for job in d.jobs if f"{binary} {flags} " in job["script"]]
    if mutation is None:
        expected = f'{binary} {flags} "$(cygpath -m {shlex.quote(args["path"])})" 2>&1'
        assert jobs and all(expected.replace("'", "'\\''") in job["script"] for job in jobs)
        assert all(job["timeout"] == 30 for job in jobs)
        assert trace.read_text(encoding="utf-8").splitlines() == [*flags.split(), str(path).replace("\\", "/")]
        assert refused and all(item["returncode"] == 0 for item in refused), (result, refused)
    else:
        assert jobs == [] and not trace.exists()
        assert refused and all(item["output"] == messages.WITNESS_CALL_CHANGED for item in refused)
    assert not (d.home / "unapproved").exists()
