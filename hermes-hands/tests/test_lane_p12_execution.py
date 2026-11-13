"""Complete-command regressions through real core tools, approval binding and bash jobs."""

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("tools.environments.base")

from hands import environment, messages, store  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401


@pytest.mark.parametrize("shape", ["compound", "cat", "page", "atomic"])
def test_appended_effects_never_reach_the_device(dispatch, monkeypatch, shape):
    d = dispatch
    execute = environment.HandsEnvironment.execute
    changed = []

    def mutate(env, command, cwd="", **kwargs):
        matches = {
            "compound": command.startswith("if [ -f ") and "sed -n " in command,
            "cat": command.startswith("cat "),
            "page": command.startswith("sed -n "),
            "atomic": command.startswith("set -e; d="),
        }
        if matches[shape]:
            command += "; printf hacked > relative.txt"
            changed.append(command)
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    if shape in {"cat", "atomic"}:
        import hermes_constants

        monkeypatch.setattr(hermes_constants, "get_subprocess_home", lambda env=None: "/home/gw")
        monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
        tool, args = "write_file", {"path": "~/work/notes.py", "content": "print('approved')\n"}
        if shape == "cat":
            (d.home / "work" / "notes.py").write_bytes(b"print('old')\n")
            from tools import file_tools

            monkeypatch.setattr(file_tools.ShellFileOperations, "_write_probe_cmd", lambda *a: "unparseable probe")
    else:
        tool, args = "read_file", {"path": f"{d.base}/work/notes.txt", "offset": 1, "limit": 1}
        if shape == "page":
            from tools import file_tools

            monkeypatch.setattr(file_tools.ShellFileOperations, "_read_probe_cmd", lambda *a: "unparseable probe")
    result = d.call(tool, args)
    assert changed, result
    assert not (d.home / "relative.txt").exists(), (result, d.outputs)
    assert not any("printf hacked" in job["script"] for job in d.jobs)
    if shape != "cat":
        assert messages.WITNESS_CALL_CHANGED in result, result
    monkeypatch.setattr(environment.HandsEnvironment, "execute", execute)
    result = d.call(tool, args)
    assert messages.WITNESS_CALL_CHANGED not in result, result
    assert not json.loads(result).get("error"), result
    if tool == "read_file":
        assert "public" in result and "private" not in result, result
    else:
        assert (d.home / "work" / "notes.py").read_bytes() == b"print('approved')\n"


@pytest.mark.parametrize("operation", ["Delete", "Add", "Move"])
def test_replacement_approval_cannot_become_a_v4a_operation(dispatch, operation):
    d = dispatch
    path = f"{d.base}/work/notes.txt"
    body = {
        "Delete": f"*** Delete File: {path}",
        "Add": f"*** Add File: {path}\n+hidden",
        "Move": f"*** Update File: {path}\n*** Move to: {d.base}/work/moved.txt\n@@\n-public\n+hidden",
    }[operation]
    before = d.files()
    d.modify = lambda args: {**args, "mode": "patch", "patch": f"*** Begin Patch\n{body}\n*** End Patch"}
    result = d.call("patch", {"path": path, "old_string": "public", "new_string": "approved"})
    assert d.files() == before, (result, d.outputs)
    assert not any("p.unlink()" in job["script"] for job in d.jobs)


@pytest.mark.parametrize("name", ["notes.txt", "notes spaced.txt", "hermes_bg_test.log"])
def test_mapped_writes_verify_and_execute_one_destination(dispatch, monkeypatch, name):
    import hermes_constants

    d = dispatch
    monkeypatch.setattr(hermes_constants, "get_subprocess_home", lambda env=None: "/home/gw")
    monkeypatch.setattr(environment, "_gateway_home", lambda: "/home/gw")
    result = json.loads(d.call("write_file", {"path": f"~/{name}", "content": "approved\n"}))
    assert not result.get("error"), (result, d.outputs)
    assert (d.home / name).read_bytes() == b"approved\n"
    assert not any("/home/gw/" in job["script"] for job in d.jobs)


@pytest.mark.skipif(os.name != "nt", reason="native drive paths need a Windows bash device")
@pytest.mark.parametrize("name", ["drive.txt", "drive spaced.txt"])
def test_mapped_drive_writes_keep_the_approved_destination(dispatch, name):
    d = dispatch
    result = json.loads(d.call("write_file", {"path": str(d.home / name), "content": "approved\n"}))
    assert not result.get("error"), (result, d.outputs)
    assert (d.home / name).read_bytes() == b"approved\n"


@pytest.mark.parametrize("windows", [False, True], ids=["posix", "windows"])
def test_unchanged_utf16_read_keeps_the_approved_page(dispatch, monkeypatch, windows):
    d = dispatch
    monkeypatch.setenv("PATH", os.pathsep.join((str(Path(sys.executable).parent), os.environ["PATH"])))
    device = store.get_device("laptop")
    monkeypatch.setattr(store, "get_device", lambda name: {**device, "os": "Windows-11" if windows else "Linux"})
    (d.home / "work" / "notes.txt").write_bytes("public\nprivate\nlast\n".encode("utf-16"))
    # The POSIX branch keeps the path inside base64. On a Windows test host use its
    # native absolute spelling so the real Python process can open the same file.
    path = str(d.home / "work" / "notes.txt") if os.name == "nt" and not windows else f"{d.base}/work/notes.txt"
    args = {"path": path, "offset": 2, "limit": 1}
    result = d.call("read_file", args)
    assert messages.WITNESS_CALL_CHANGED not in result, (result, d.outputs)
    assert "private" in result and "public" not in result and "last" not in result, result
    d.modify = lambda args: {**args, "offset": 1}
    result = d.call("read_file", args)
    assert "public" not in result and messages.WITNESS_CALL_CHANGED in result, result


@pytest.mark.parametrize("encoded", ["A", "////"])
def test_malformed_snippets_return_the_existing_refusal(dispatch, monkeypatch, encoded):
    d = dispatch
    execute = environment.HandsEnvironment.execute

    def mutate(env, command, cwd="", **kwargs):
        return execute(env, f"python3 -c \"import base64; exec(base64.b64decode('{encoded}').decode())\"", cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    result = d.call("read_file", {"path": f"{d.base}/work/notes.txt"})
    assert messages.WITNESS_CALL_CHANGED in result, result
    assert d.jobs == []


def test_search_executable_is_rebuilt_instead_of_taken_from_the_command(dispatch, monkeypatch):
    d = dispatch
    rogue = d.home / "relative" / "rg"
    rogue.parent.mkdir()
    rogue.write_text("#!/bin/sh\nprintf hacked > relative.txt\n", encoding="utf-8")
    rogue.chmod(0o755)
    execute = environment.HandsEnvironment.execute

    def mutate(env, command, cwd="", **kwargs):
        if command.startswith("set -o pipefail; grep "):
            command = (
                "set -o pipefail; relative/rg --line-number --no-heading --with-filename "
                f"--max-columns 2000 --max-columns-preview 'public' '{d.base}/work' | head -n 50"
            )
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    result = d.call("search_files", {"path": f"{d.base}/work", "pattern": "public"})
    assert not (d.home / "relative.txt").exists(), (result, d.outputs)
    assert not any("relative/rg" in job["script"] for job in d.jobs)
    assert messages.WITNESS_CALL_CHANGED in result, result


@pytest.mark.skipif(os.name != "nt", reason="uses the bash device's real Windows drive aliases")
@pytest.mark.parametrize("direction", ["posix-to-drive", "drive-to-posix"])
def test_posix_gateway_search_refuses_drive_alias_changes(dispatch, monkeypatch, direction):
    from tools.environments import local

    d = dispatch
    monkeypatch.setattr(local, "_IS_WINDOWS", False)
    monkeypatch.setattr(environment, "os", SimpleNamespace(**{**vars(environment.os), "name": "posix"}))
    posix_root = f"{d.base}/work"
    drive_root = f"{posix_root[1].upper()}:{posix_root[2:]}"
    root, alternate = (posix_root, drive_root) if direction == "posix-to-drive" else (drive_root, posix_root)
    args = {"path": root, "pattern": "public"}
    unchanged = d.call("search_files", args)
    assert "notes.txt" in unchanged and "public" in unchanged, (unchanged, d.outputs)
    assert messages.WITNESS_CALL_CHANGED not in unchanged, unchanged
    execute = environment.HandsEnvironment.execute
    changed = []

    def mutate(env, command, cwd="", **kwargs):
        if command.startswith("set -o pipefail; grep "):
            command = command.replace(environment._quoted(root), environment._quoted(alternate))
            changed.append(command)
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    d.jobs.clear()
    result = d.call("search_files", args)
    assert changed, result
    assert messages.WITNESS_CALL_CHANGED in result, result
    assert not any(command in job["script"] for command in changed for job in d.jobs)
    monkeypatch.setattr(environment.HandsEnvironment, "execute", execute)
    unchanged = d.call("search_files", args)
    assert "notes.txt" in unchanged and "public" in unchanged, (unchanged, d.outputs)
    assert messages.WITNESS_CALL_CHANGED not in unchanged, unchanged


def test_search_target_alias_is_rebuilt_with_the_registered_core_handler(dispatch):
    d = dispatch
    args = {"path": f"{d.base}/work", "pattern": "*.txt", "target": "find"}
    result = d.call("search_files", args)
    assert any(path.endswith("/notes.txt") for path in json.loads(result).get("files", [])), result
    assert not json.loads(result).get("error"), result
    d.modify = lambda args: {**args, "target": "content"}
    result = d.call("search_files", args)
    assert messages.WITNESS_CALL_CHANGED in result, result


@pytest.mark.parametrize("target", ["files", "find"])
def test_invalid_approved_search_order_cannot_become_a_traversal(dispatch, target):
    d = dispatch
    args = {"path": f"{d.base}/work", "pattern": "*.txt", "target": target, "order": "invalid"}
    result = d.call("search_files", args)
    assert "Invalid file search order" in result, result
    assert d.jobs == []
    d.modify = lambda args: {**args, "order": "discovery"}
    result = d.call("search_files", args)
    assert messages.WITNESS_CALL_CHANGED in result, result
    assert d.jobs == []
