"""Copied command templates must agree with the real core used for this test run."""

import asyncio
import base64
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("tools.file_operations")

from hands import environment  # noqa: E402
from tools.file_operations import ShellFileOperations  # noqa: E402
from tools.file_operations_common import ExecuteResult  # noqa: E402
from tools.tool_output_limits import get_max_line_length  # noqa: E402


PATH = "/approved/notes.txt"


@pytest.fixture
def captured(monkeypatch):
    ops = ShellFileOperations(SimpleNamespace(cwd="/approved", uses_host_filesystem=False, is_local=False))
    commands = []

    def execute(command, **kwargs):
        commands.append((command, kwargs.get("stdin_data")))
        return ExecuteResult(stdout="", exit_code=1)

    monkeypatch.setattr(ops, "_exec", execute)
    monkeypatch.setattr(ops, "_native_read_enabled", lambda: False)
    return ops, commands


@pytest.mark.parametrize("path", [PATH, "/approved/a spaced 'name'.txt", "C:/Users/person/notes.txt"])
def test_atomic_write_template_equals_real_core(captured, path):
    ops, commands = captured
    ops._atomic_write(path, "approved bytes\n")
    assert commands == [(environment._atomic_write_command(path), "approved bytes\n")]
    command = commands[0][0]
    assert command in environment._file_candidates("write_file", {}, path, command)
    altered = command + "; printf hacked > relative.txt"
    assert altered not in environment._file_candidates("write_file", {}, path, altered)


@pytest.mark.parametrize("offset,limit", [(1, 1), (2, 7), (91, 2000)])
def test_utf16_program_equals_real_core(captured, offset, limit):
    ops, commands = captured
    ops._try_read_utf16(PATH, offset, limit, 10)
    command, stdin = commands[0]
    encoded = re.search(r"b64decode\('([^']+)'\)", command).group(1)
    assert base64.b64decode(encoded).decode() == environment._utf16_program(PATH, offset, limit)
    assert stdin is None
    assert command in environment._file_candidates("read_file", {"offset": offset, "limit": limit}, PATH, command)
    program = base64.b64decode(encoded).decode()
    for altered_program in (program.replace(PATH, "/approved/other.txt"), program + "os.unlink('relative.txt')\n"):
        altered = command.replace(encoded, base64.b64encode(altered_program.encode()).decode())
        assert altered not in environment._file_candidates("read_file", {"offset": offset, "limit": limit}, PATH, altered)


@pytest.mark.parametrize("tool", ["read_file", "write_file", "patch"])
@pytest.mark.parametrize("helper", ["regular", "sample", "head", "exact", "hex"])
def test_file_helper_templates_equal_real_core(captured, tool, helper):
    ops, commands = captured
    if helper == "regular":
        ops._probe_regular_file(PATH)
    elif helper == "sample":
        ops._sample_file_bytes(PATH)
    elif helper == "head":
        ops._head(PATH, 1000 if tool == "read_file" else 3)
    elif helper == "exact":
        ops._read_exact_bytes(PATH)
    else:
        ops._read_exact_bytes_hex(PATH)
    for command, stdin in commands:
        if tool == "read_file" and helper in {"exact", "hex"}:
            assert command not in environment._file_candidates(tool, {}, PATH, command)
        else:
            assert command in environment._file_candidates(tool, {}, PATH, command), command
        assert stdin is None
        altered = command + "; printf hacked > relative.txt"
        assert altered not in environment._file_candidates(tool, {}, PATH, altered)


@pytest.mark.parametrize("offset,limit", [(1, 1), (3, 9)])
def test_compound_read_template_equals_real_core(captured, offset, limit):
    ops, _ = captured
    command = ops._read_probe_cmd(PATH, offset, offset + limit - 1, 4 * get_max_line_length() + 1,
                                  "__HERMES_RF_" + "a" * 32 + "__")
    args = {"offset": offset, "limit": limit}
    assert command in environment._file_candidates("read_file", args, PATH, command)
    assert command not in environment._file_candidates("read_file", {"offset": offset + 1, "limit": limit}, PATH, command)
    altered = command + "; printf hacked > relative.txt"
    assert altered not in environment._file_candidates("read_file", args, PATH, altered)


def test_read_template_respects_real_core_configured_limits(captured, monkeypatch):
    from hermes_cli import config
    from tools import tool_output_limits

    monkeypatch.setattr(config, "load_config", lambda: {"tool_output": {"max_lines": 4, "max_line_length": 19}})
    monkeypatch.setattr(tool_output_limits, "_cached_limits", {})
    ops, commands = captured
    ops.read_file(PATH, offset=3, limit=2000)
    command = commands[0][0]
    assert "sed -n '3,6p'" in command
    assert "cut -b1-77" in command
    assert command in environment._file_candidates("read_file", {"offset": 3, "limit": 2000}, PATH, command)


@pytest.mark.parametrize("body", [None, "cat", "sample"])
@pytest.mark.parametrize("tool", ["write_file", "patch"])
def test_write_probe_template_equals_real_core(captured, tool, body):
    ops, _ = captured
    command = ops._write_probe_cmd(PATH, "__HERMES_WF_" + "b" * 32 + "__", body)
    assert command in environment._file_candidates(tool, {}, PATH, command)
    altered = command + "; printf hacked > relative.txt"
    assert altered not in environment._file_candidates(tool, {}, PATH, altered)


@pytest.mark.parametrize("operation", ["delete", "move"])
def test_replacement_candidates_exclude_real_core_other_operations(captured, operation):
    ops, commands = captured
    if operation == "delete":
        ops.delete_file(PATH)
    else:
        ops.move_file(PATH, "/approved/moved.txt")
    assert commands
    for command, _ in commands:
        assert command not in environment._file_candidates("patch", {"old_string": "one", "new_string": "two"}, PATH, command)


@pytest.mark.parametrize("helper", ["cat", "bom", "sample", "hash"])
def test_write_metadata_templates_equal_real_core(captured, helper):
    ops, commands = captured
    if helper == "cat":
        ops._cat(PATH)
    elif helper == "bom":
        ops._file_has_bom(PATH)
    elif helper == "sample":
        ops._head(PATH, 4096)
    else:
        ops._verify_written_hash(PATH, b"approved bytes")
    assert commands
    for command, stdin in commands:
        assert command in environment._file_candidates("write_file", {}, PATH, command)
        assert stdin is None


@pytest.mark.parametrize("mode,context", [("content", 0), ("content", 2), ("files_only", 0), ("count", 0)])
@pytest.mark.parametrize("root", ["/approved", "/approved/.hidden", "relative"])
def test_grep_search_template_equals_real_core(captured, root, mode, context):
    ops, commands = captured
    ops._search_with_grep("public", root, "*.txt", 5, 2, mode, context)
    args = {"pattern": "public", "file_glob": "*.txt", "limit": 5, "offset": 2,
            "output_mode": mode, "context": context}
    assert commands
    for command, stdin in commands:
        assert environment._searched(args, command, {root}), command
        assert not environment._searched(args, command + "; printf hacked > relative.txt", {root})
        assert stdin is None


@pytest.mark.parametrize("order", ["discovery", "modified"])
@pytest.mark.parametrize("root", ["/approved", "-relative"])
def test_filename_search_template_equals_real_core(captured, monkeypatch, order, root):
    ops, commands = captured
    monkeypatch.setattr(ops, "_has_command", lambda name: name == "find")
    monkeypatch.setattr(ops, "_is_broad_local_search_root", lambda path: False)
    ops._search_files("**/*.txt", root, 5, 2, order)
    args = {"pattern": "**/*.txt", "target": "files", "limit": 5, "offset": 2, "order": order}
    assert commands
    for command, stdin in commands:
        assert environment._searched(args, command, {root}), command
        assert not environment._searched(args, command + "; printf hacked > relative.txt", {root})
        assert stdin is None


@pytest.mark.parametrize("target,pattern,mode,context", [
    ("content", "public", "content", 0),
    ("content", r"one\ntwo", "content", 2),
    ("content", "public", "files_only", 0),
    ("content", "public", "count", 0),
    ("files", "*.txt", "content", 0),
])
def test_rg_search_template_equals_real_core(captured, monkeypatch, target, pattern, mode, context):
    ops, commands = captured
    monkeypatch.setattr(ops, "_resolve_command", lambda name: "rg")
    monkeypatch.setattr(ops, "_has_command", lambda name: False)
    if target == "files":
        ops._search_files_rg(pattern, "/approved", 5, 2, rg_executable="rg")
    else:
        ops._search_with_rg(pattern, "/approved", "*.txt", 5, 2, mode, context, rg_executable="rg")
    args = {"pattern": pattern, "target": target, "file_glob": "*.txt", "limit": 5,
            "offset": 2, "output_mode": mode, "context": context}
    assert commands
    for command, stdin in commands:
        assert environment._searched(args, command, {"/approved"}), command
        assert not environment._searched(args, command + "; printf hacked > relative.txt", {"/approved"})
        assert stdin is None


@pytest.mark.parametrize("windows", [False, True], ids=["posix-gateway", "windows-gateway"])
@pytest.mark.parametrize("root", ["/c/approved", "C:/approved", "/cygdrive/c/approved", "/mnt/c/approved"])
@pytest.mark.parametrize("engine", ["rg", "grep"])
def test_search_path_conversion_equals_real_core(captured, monkeypatch, windows, root, engine):
    from tools.environments import local

    ops, commands = captured
    monkeypatch.setattr(local, "_IS_WINDOWS", windows)
    monkeypatch.setattr(environment, "os", SimpleNamespace(**{**vars(environment.os), "name": "nt" if windows else "posix"}))
    if engine == "rg":
        ops._search_with_rg("public", root, None, 5, 0, "content", 0, rg_executable="rg")
    else:
        ops._search_with_grep("public", root, None, 5, 0, "content", 0)
    args = {"pattern": "public", "limit": 5}
    assert commands
    for command, _ in commands:
        assert environment._searched(args, command, {root}), command
        if not windows:
            alternate = "C:/approved" if root.startswith("/") else "/c/approved"
            changed = command.replace(environment._quoted(root), environment._quoted(alternate))
            assert changed != command
            assert not environment._searched(args, changed, {root})


@pytest.mark.parametrize("path", ["/approved/image.png", "/approved/a spaced 'image'.png"])
def test_vision_read_template_equals_real_core(monkeypatch, path):
    from tools import image_source

    commands = []

    def execute(command):
        commands.append(command)
        return {"output": base64.b64encode(b"<svg></svg>").decode(), "returncode": 0}

    monkeypatch.setattr(image_source, "_ensure_container_env", lambda task_id: None)
    monkeypatch.setattr(image_source, "_get_active_env", lambda task_id: SimpleNamespace(execute=execute))
    result = asyncio.run(image_source._resolve_container_fallback(
        Path(path), image_source.ResolveContext(task_id="template"), path, ("image",)))
    assert result.data == b"<svg></svg>"
    assert len(commands) == 1
    command = commands[0]
    assert command in environment._file_candidates("vision_analyze", {}, path, command)
    altered = command + "; printf hacked > relative.txt"
    assert altered not in environment._file_candidates("vision_analyze", {}, path, altered)
