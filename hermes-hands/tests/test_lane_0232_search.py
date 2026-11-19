"""Both pinned core search spellings must match whole approved commands."""

from types import SimpleNamespace

import pytest

pytest.importorskip("tools.file_operations")

from hands import environment  # noqa: E402
from tools.file_operations import ShellFileOperations  # noqa: E402
from tools.file_operations_common import ExecuteResult  # noqa: E402


@pytest.mark.parametrize("delimited", [False, True], ids=["0231", "0232"])
@pytest.mark.parametrize("engine", ["rg", "grep", "find"])
@pytest.mark.parametrize("mode", ["content", "files_only", "count"])
@pytest.mark.parametrize("pattern", ["public", "--version"])
def test_both_core_pattern_spellings_are_exact(delimited, engine, mode, pattern):
    args = {"pattern": pattern, "limit": 5, "output_mode": mode}
    argument = f"'{pattern}'"
    operand = f"-e {argument} --" if delimited else argument
    mode_flag = {"content": "", "files_only": " -l", "count": " -c"}[mode]
    if engine == "rg":
        columns = " --max-columns 2000 --max-columns-preview" if mode == "content" else ""
        body = f"rg --line-number --no-heading --with-filename{columns}{mode_flag} {operand} '/approved'"
    elif engine == "grep":
        body = f"grep -rnHE --exclude-dir='.*'{mode_flag} {operand} '/approved'"
    else:
        body = (
            "find -H '/approved' \\( -type d -name '.*' ! -path '/approved' \\) -prune "
            f"-o -type f -exec grep -nHE{mode_flag} {operand} {{}} +"
        )
    cut = " | cut -c1-2000" if engine != "rg" and mode == "content" else ""
    command = f"set -o pipefail; {body} | head -n 5{cut}"
    assert environment._searched(args, command, {"/approved"})
    for altered in (
        command + "; printf changed",
        command.replace("'/approved'", "'/elsewhere'"),
        command.replace(argument, "'unapproved'"),
        command.replace("head -n 5", "head -n 6"),
        command.replace(operand, f"-e {argument}"),
        command.replace(operand, f"{argument} --"),
        command.replace(operand, f"-e {argument} -e 'unapproved' --"),
        command.replace(operand, f"-F {operand}"),
        command.replace(operand, f"{operand} '/elsewhere'"),
    ):
        assert not environment._searched(args, altered, {"/approved"}), altered


@pytest.mark.parametrize("delimited", [False, True], ids=["0231", "0232"])
@pytest.mark.parametrize("flag", ["-i", "-F"])
def test_both_core_hint_spellings_are_exact(delimited, flag):
    operand = "-e 'public[0]' --" if delimited else "'public[0]'"
    command = f"rg {flag} --count-matches  {operand} '/approved' 2>/dev/null | head -n 50"
    args = {"pattern": "public[0]"}
    assert environment._searched(args, command, {"/approved"})
    assert not environment._searched(args, command + "; printf changed", {"/approved"})
    assert not environment._searched(args, command.replace(operand, "-e 'public[0]'"), {"/approved"})
    assert not environment._searched(args, command.replace(operand, "'public[0]' --"), {"/approved"})


def test_all_real_core_zero_match_probes_are_exact(monkeypatch):
    ops = ShellFileOperations(SimpleNamespace(cwd="/approved", uses_host_filesystem=False, is_local=False))
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        return ExecuteResult(stdout="", exit_code=1)

    monkeypatch.setattr(ops, "_resolve_command", lambda name: "rg")
    monkeypatch.setattr(ops, "_exec", execute)
    assert ops._zero_match_probe("public[0]", "/approved", "*.txt") is None
    assert len(commands) == 3
    for command in commands:
        args = {"pattern": "public[0]", "file_glob": "*.txt"}
        assert environment._searched(args, command, {"/approved"})
        assert not environment._searched(args, command + "; printf changed", {"/approved"})


@pytest.mark.parametrize("separator", ["", "-- "])
def test_both_missing_path_hints_are_exact(separator):
    command = f"ls -1 {separator}'/approved' 2>/dev/null | head -20"
    candidates = environment._file_candidates("search_files", {}, "/approved/missing", command)
    assert command in candidates
    assert command + "; printf changed" not in candidates


def test_real_core_missing_path_hint_is_exact(monkeypatch):
    ops = ShellFileOperations(SimpleNamespace(cwd="/approved", uses_host_filesystem=False, is_local=False))
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        return ExecuteResult(stdout="yes\n" if command.startswith("test -d ") else "missing_sibling.txt\n", exit_code=0)

    monkeypatch.setattr(ops, "_exec", execute)
    result = ops._path_not_found_result("/approved/missing")
    assert "missing_sibling.txt" in result.error
    assert len(commands) == 2
    for command in commands:
        candidates = environment._file_candidates("search_files", {}, "/approved/missing", command)
        assert command in candidates
        assert command + "; printf changed" not in candidates
