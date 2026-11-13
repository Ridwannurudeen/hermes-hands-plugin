"""Approval binds every input at the real core execution boundary."""

import contextvars
import inspect
import json
import shlex

import pytest

pytest.importorskip("tools.environments.base")

from hands import environment, messages  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401


def test_execution_input_inventory_matches_both_core_contracts():
    from hands import client
    from hands.handle import RemoteProcessHandle
    from tools.environments.base import BaseEnvironment
    from tools.read_extract import ANYDOC_EXTENSIONS, EXTRACTABLE_EXTENSIONS

    assert environment._DOCUMENT_EXTENSIONS == ANYDOC_EXTENSIONS | EXTRACTABLE_EXTENSIONS
    assert list(inspect.signature(BaseEnvironment.execute).parameters) == [
        "self", "command", "cwd", "timeout", "stdin_data", "rewrite_compound_background",
        "bounded_capture", "yield_handler",
    ]
    assert list(inspect.signature(RemoteProcessHandle).parameters) == [
        "device", "script", "login", "timeout", "inline_limit", "stdin", "file_op",
    ]
    assert list(inspect.signature(client.start_job).parameters) == [
        "device", "script", "login", "timeout", "stdin", "file_op",
    ]


@pytest.mark.parametrize("command", ["tee /tmp/notes.txt", "git apply -"])
def test_terminal_rejects_unapproved_stdin(dispatch, monkeypatch, command):
    d = dispatch
    execute = environment.HandsEnvironment.execute

    def mutate(env, command, cwd="", **kwargs):
        return execute(env, command, cwd, **{**kwargs, "stdin_data": "unapproved bytes\n"})

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    result = d.call("terminal", {"command": command})
    assert messages.WITNESS_CALL_CHANGED in result, result
    assert d.jobs == []


@pytest.mark.parametrize("tool,args", [
    ("read_file", {"path": "notes.txt", "offset": 1, "limit": 1}),
    ("search_files", {"path": ".", "pattern": "public"}),
    ("search_files", {"path": "work", "pattern": "public"}),
])
def test_relative_operations_reject_changed_cwd(dispatch, monkeypatch, tool, args):
    d = dispatch
    execute = environment.HandsEnvironment.execute

    def mutate(env, command, cwd="", **kwargs):
        return execute(env, command, f"{d.base}/archive", **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    result = d.call(tool, args)
    assert messages.WITNESS_CALL_CHANGED in result, result
    assert d.jobs == []


@pytest.mark.parametrize("tool", ["terminal", "read_file", "search_files", "write_file", "patch"])
@pytest.mark.parametrize("field,value", [
    ("timeout", 731), ("env", {"EXTRA": "unapproved"}), ("login", True),
    ("yield_handler", lambda *args: {}), ("rewrite_compound_background", False),
    ("bounded_capture", "unapproved"), ("_hands_mapped", True),
])
def test_undeclared_execution_inputs_fail_closed(dispatch, monkeypatch, tool, field, value):
    d = dispatch
    execute = environment.HandsEnvironment.execute
    refusals = []

    def mutate(env, command, cwd="", **kwargs):
        result = execute(env, command, cwd, **{**kwargs, field: value})
        refusals.append(result)
        return result

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    args = {
        "terminal": {"command": "pwd"},
        "read_file": {"path": f"{d.base}/work/notes.txt"},
        "search_files": {"path": f"{d.base}/work", "pattern": "public"},
        "write_file": {"path": f"{d.base}/work/new.txt", "content": "approved"},
        "patch": {"path": f"{d.base}/work/notes.txt", "old_string": "public", "new_string": "approved"},
    }[tool]
    before = d.files()
    result = d.call(tool, args)
    assert d.jobs == [], (result, d.outputs)
    assert d.files() == before
    assert refusals and all(messages.WITNESS_CALL_CHANGED in item["output"] for item in refusals), (result, refusals)


@pytest.mark.parametrize("argument", ["~/../Public/notes.txt", "absolute"])
def test_original_argument_defines_single_home_destination(dispatch, monkeypatch, argument):
    import hermes_constants

    d = dispatch
    gateway = f"{d.base}/gateway"
    (d.home / "gateway").mkdir()
    (d.home.parent / "Public").mkdir()
    monkeypatch.setattr(hermes_constants, "get_subprocess_home", lambda env=None: gateway)
    monkeypatch.setattr(environment, "_gateway_home", lambda: gateway)
    path = f"{gateway}/notes.txt" if argument == "absolute" else argument
    destination = d.home / "gateway" / "notes.txt" if argument == "absolute" else d.home.parent / "Public" / "notes.txt"
    result = d.call("write_file", {"path": path, "content": "approved\n"})
    assert not json.loads(result).get("error"), (result, d.outputs)
    assert destination.read_bytes() == b"approved\n"
    assert not (d.home / "notes.txt").exists()


def test_tilde_alone_names_device_home(dispatch, monkeypatch):
    d = dispatch
    monkeypatch.setenv("HOME", d.base)
    result = d.call("search_files", {"path": "~", "pattern": "public"})
    assert "notes.txt" in result and "public" in result, (result, d.outputs)
    assert messages.WITNESS_CALL_CHANGED not in result


@pytest.mark.parametrize("extension", ["pdf", "docx", "xlsx", "pptx"])
@pytest.mark.parametrize("relative,paged", [(True, False), (True, True), (False, True)])
def test_documents_transfer_exact_whole_file_before_pagination(dispatch, monkeypatch, extension, relative, paged):
    from tools import read_extract

    d = dispatch
    payload = b"approved document bytes"
    (d.home / f"report.{extension}").write_bytes(payload)
    seen = []

    def extract(data, path):
        seen.append((data, path))
        return "public\nprivate\nlast\n"

    monkeypatch.setattr(read_extract, "_anydoc", lambda: object())
    monkeypatch.setattr(read_extract, "extract_document_bytes", extract)
    path = f"report.{extension}" if relative else f"{d.base}/report.{extension}"
    args = {"path": path, **({"offset": 2, "limit": 1} if paged else {})}
    result = d.call("read_file", args)
    assert not json.loads(result).get("error"), (result, d.outputs)
    assert seen == [(payload, f"{d.base}/report.{extension}")]
    assert "private" in result
    if paged:
        assert "public" not in json.loads(result)["content"] and "last" not in json.loads(result)["content"]
    transport = f"base64 < '{d.base}/report.{extension}'".replace("'", "'\\''")
    assert any(transport in job["script"] for job in d.jobs)
    d.jobs.clear()
    execute = environment.HandsEnvironment.execute
    refusals = []

    def mutate(env, command, cwd="", **kwargs):
        command = command.replace(f"report.{extension}", f"other.{extension}")
        result = execute(env, command, cwd, **kwargs)
        refusals.append(result)
        return result

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    result = d.call("read_file", args)
    assert d.jobs == [] and len(seen) == 1, result
    assert refusals and all(item["output"] == messages.WITNESS_CALL_CHANGED for item in refusals), (result, refusals)


def test_relative_document_keeps_device_destination_with_gateway_cwd(dispatch, monkeypatch):
    from tools import read_extract

    d = dispatch
    (d.home / "report.docx").write_bytes(b"approved document")
    monkeypatch.setenv("TERMINAL_CWD", "/gateway/workspace")
    monkeypatch.setattr(read_extract, "extract_document_bytes", lambda data, path: data.decode())
    result = d.call("read_file", {"path": "report.docx", "offset": 1, "limit": 1})
    assert "approved document" in result, (result, d.outputs)
    assert not json.loads(result).get("error"), result


def test_write_preserves_crlf_after_multibyte_characters(dispatch):
    d = dispatch
    path = d.home / "work" / "notes.py"
    path.write_bytes(("#" + "é" * 2500 + "\r\n").encode("utf-8"))
    result = d.call("write_file", {"path": f"{d.base}/work/notes.py", "content": "pass\n"})
    assert not json.loads(result).get("error"), (result, d.outputs)
    assert path.read_bytes() == b"pass\r\n"


@pytest.mark.parametrize("kind", ["exit", "log", "probe"])
@pytest.mark.parametrize("change", ["directory", "relative", "stdin", "cwd", "timeout", "env", "login"])
def test_background_polls_bind_launched_artifacts_and_inputs(dispatch, monkeypatch, kind, change):
    from tools import terminal_tool
    from tools.process_registry import process_registry

    d = dispatch
    poll_context = []
    monkeypatch.setattr(process_registry, "_track_started", lambda *args: poll_context.append(contextvars.copy_context()))
    result = json.loads(d.call("terminal", {"command": "pwd", "background": True}))
    assert result.get("session_id"), (result, d.outputs)
    job = result["session_id"]
    env = next(env for env in terminal_tool._active_environments.values() if isinstance(env, environment.HandsEnvironment))
    temp = env.get_temp_dir().rstrip("/")
    directory = "/elsewhere" if change == "directory" else "." if change == "relative" else temp
    path = shlex.quote(f"{directory}/hermes_bg_{job}.{'pid' if kind == 'probe' else kind}")
    command = {
        "exit": f"cat {path} 2>/dev/null",
        "probe": f'kill -0 "$(cat {path} 2>/dev/null)" 2>/dev/null; echo $?',
        "log": environment._log_delta_command(path, 0),
    }[kind]
    kwargs = {"timeout": 10 if kind == "log" else 5}
    kwargs.update({
        "stdin": {"stdin_data": "unapproved"}, "cwd": {"cwd": f"{d.base}/archive"},
        "timeout": {"timeout": 731}, "env": {"env": {"EXTRA": "unapproved"}},
        "login": {"login": True},
    }.get(change, {}))
    d.jobs.clear()
    refused = poll_context[0].copy().run(env.execute, command, **kwargs)
    assert messages.WITNESS_CALL_CHANGED in refused["output"], refused
    assert d.jobs == []
    # Exact canonical polling continues to work after the refusal.
    canonical = shlex.quote(f"{temp}/hermes_bg_{job}.{'pid' if kind == 'probe' else kind}")
    accepted = {
        "exit": f"cat {canonical} 2>/dev/null",
        "probe": f'kill -0 "$(cat {canonical} 2>/dev/null)" 2>/dev/null; echo $?',
        "log": environment._log_delta_command(canonical, 0),
    }[kind]
    poll_context[0].copy().run(env.execute, accepted, timeout=10 if kind == "log" else 5)
    assert len(d.jobs) == 1


@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("binary", ["node", "npx", "go", "rustfmt"])
def test_exact_optional_linter_availability_probes(dispatch, monkeypatch, tool, binary):
    from tools import file_operations_lint, file_tools

    d = dispatch
    # Force this core linter branch for a harmless text file without invoking a compiler.
    monkeypatch.setitem(file_operations_lint.LINTERS, ".txt", f"{binary} --check {{file}} 2>&1")
    args = {"path": f"{d.base}/work/notes.txt", **(
        {"content": "approved\n"} if tool == "write_file" else {"old_string": "public", "new_string": "approved"}
    )}
    result = d.call(tool, args)
    probe = f"command -v {binary} >/dev/null 2>&1 && echo 'yes'"
    assert any(probe.replace("'", "'\\''") in job["script"] for job in d.jobs), (result, d.outputs)
    d.jobs.clear()
    (d.home / "work" / "notes.txt").write_bytes(b"public\nprivate\nlast\n")
    file_tools.clear_file_ops_cache()
    execute = environment.HandsEnvironment.execute
    changed = []
    refusals = []

    def mutate(env, command, cwd="", **kwargs):
        if command == probe:
            command += "; printf hacked > relative.txt"
            changed.append(command)
        result = execute(env, command, cwd, **kwargs)
        if command in changed:
            refusals.append(result)
        return result

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    d.call(tool, args)
    assert changed
    assert all(item["output"] == messages.WITNESS_CALL_CHANGED for item in refusals)
    assert not (d.home / "relative.txt").exists()
    assert not any("printf hacked" in job["script"] for job in d.jobs)
