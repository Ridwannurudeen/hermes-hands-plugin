"""Lane 8 command-matcher regressions against real core tools and paired-laptop jobs.
The imported ``core`` fixture stubs ``client.shown_call``; these tests do not prove
human approval. Real hook, gate and dispatch coverage is in test_lane_p8_findings.py.
The direct witness-hook test below checks absolute-path policy only."""

import base64

import pytest

pytest.importorskip("tools.environments.base")

from hands import environment, messages, witness  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401  (fixtures)
from test_environment import (  # noqa: E402,F401  (fixtures)
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p3_shown import DEVICE, TASK, core  # noqa: E402,F401  (fixtures)


@pytest.fixture
def work(core):
    (core.home / "work" / "notes.txt").write_bytes(b"public\nprivate\nlast\n")
    (core.home / "work" / "other.log").write_bytes(b"private\n")
    return f"{core.base}/work"


@pytest.mark.parametrize("approved,changed", [
    ({"pattern": "public", "file_glob": "*.txt"}, {"pattern": "private", "file_glob": None}),
    ({"pattern": "public", "output_mode": "files_only"}, {"pattern": "public", "output_mode": "count"}),
    ({"pattern": "public", "output_mode": "count"}, {"pattern": "public", "output_mode": "content"}),
    ({"pattern": "public", "context": 1}, {"pattern": "public"}),
    ({"pattern": "public", "limit": 5, "offset": 0}, {"pattern": "public", "limit": 4, "offset": 1}),
    ({"pattern": "*.txt", "target": "files"}, {"pattern": "*.log", "target": "files"}),
    ({"pattern": "*.txt", "target": "files"}, {"pattern": "*.txt"}),
])
def test_search_matcher_requires_every_shown_argument(core, work, approved, changed):
    core.show("search_files", {**approved, "path": work})
    assert "notes.txt" in core.files.search_tool(**approved, path=work, task_id=TASK)
    result = core.files.search_tool(**changed, path=work, task_id=TASK)
    assert "notes.txt" not in result and "other.log" not in result, result


def test_read_matcher_requires_the_shown_page(core, work):
    target = f"{work}/notes.txt"
    core.show("read_file", {"path": target, "offset": 2, "limit": 1})
    assert "private" in core.files.read_file_tool(target, offset=2, limit=1, task_id=TASK)
    for offset, limit in [(1, 1), (2, 2), (1, 3)]:
        result = core.files.read_file_tool(target, offset=offset, limit=limit, task_id=TASK)
        assert "public" not in result and "last" not in result, (offset, limit, result)


@pytest.mark.parametrize("existing", [None, b"old\n"])
@pytest.mark.parametrize("injected", ["\ufeffone\ntwo\n", "one\rtwo\r", "one\r\ntwo\r\n"])
def test_a_write_never_adds_a_bom_or_cr_the_file_does_not_have(core, existing, injected):
    notes = core.home / "work" / "notes.txt"
    if existing is not None:
        notes.write_bytes(existing)
    target = f"{core.base}/work/notes.txt"
    core.show("write_file", {"path": target, "content": "one\ntwo\n"})
    assert messages.WITNESS_CALL_CHANGED in core.files.write_file_tool(target, injected, task_id=TASK)
    assert (notes.read_bytes() if existing else notes.exists()) == (existing or False)
    assert messages.WITNESS_CALL_CHANGED not in core.files.write_file_tool(target, "one\ntwo\n", task_id=TASK)
    assert notes.read_bytes() == b"one\ntwo\n"


def test_a_patch_never_adds_a_cr_to_a_file_without_line_ends(core):
    notes = core.home / "work" / "notes.txt"
    notes.write_bytes(b"a b c")
    target = f"{core.base}/work/notes.txt"
    core.show("patch", {"mode": "replace", "path": target, "old_string": "b", "new_string": "x\ny"})
    core.files.patch_tool(mode="replace", path=target, old_string="b", new_string="x\ry", task_id=TASK)
    assert notes.read_bytes() == b"a b c"
    core.files.patch_tool(mode="replace", path=target, old_string="b", new_string="x\ny", task_id=TASK)
    assert notes.read_bytes() == b"a x\ny c"


def test_shown_workdir_that_is_another_targets_record_is_kept(core):
    work = f"{core.base}/work"
    environment._SESSION_CWDS[TASK] = {"server": work, "laptop": core.base}
    core.show("terminal", {"command": "pwd", "workdir": work})
    result = core.terminal.terminal_tool("pwd", task_id=TASK, workdir=work)
    assert f'{work}", "exit_code": 0' in result, result
    assert environment._SESSION_CWDS[TASK]["laptop"] == core.base


@pytest.mark.parametrize("tool,extra", [("write_file", {"content": "x"}), ("patch", {"old_string": "a", "new_string": "b"})])
@pytest.mark.parametrize("path,blocked", [
    ("notes.txt", True), ("work/notes.txt", True), ("./notes.txt", True), ("C:/Users/../notes.txt", True), ("C:/Users/sam/notes.txt", False),
    ("/home/sam/notes.txt", False), ("/c/Users/sam/notes.txt", False),
])
def test_a_witness_write_or_patch_needs_an_absolute_path(monkeypatch, tool, extra, path, blocked):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    decision = witness.pre_tool_call(None, tool, {"path": path, **extra}, session_id="s1", tool_call_id="c1")
    assert (decision == {"action": "block", "message": messages.WITNESS_ABSOLUTE_PATH_REQUIRED}) is blocked, decision


@pytest.mark.parametrize("extension", ["pdf", "docx", "png"])
def test_whole_document_transport_preserves_exact_path_with_pagination(core, monkeypatch, extension):
    from tools import read_extract

    target = f"{core.base}/work/document.{extension}"
    monkeypatch.setattr(read_extract, "_anydoc", lambda: object())
    data = b"whole document bytes"
    (core.home / "work" / f"document.{extension}").write_bytes(data)
    core.show("read_file", {"path": target})
    commands = []
    execute = environment.HandsEnvironment.execute

    def capture(env, command, cwd="", **kwargs):
        commands.append(command)
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", capture)
    if extension == "png":
        result = core.files._get_file_ops(TASK).read_file_bytes(target)
        assert result.base64_content is not None, result
    else:
        def extract(content, path):
            assert content == data and str(path).endswith(extension)
            return "document text"
        monkeypatch.setattr(read_extract, "extract_document_bytes", extract)
        assert "document text" in core.files.read_file_tool(target, task_id=TASK)
    command = f"base64 < '{target}'"
    assert command in commands
    env = core.files._get_file_ops(TASK).env
    assert execute(env, command + "; echo extra")["output"] == messages.WITNESS_CALL_CHANGED
    assert execute(env, f"base64 < '{core.base}/work/other.{extension}'")["output"] == messages.WITNESS_CALL_CHANGED
    for page in ({"offset": 1}, {"limit": 1}):
        core.show("read_file", {"path": target, **page})
        if extension == "png":
            assert execute(env, command)["output"] == messages.WITNESS_CALL_CHANGED
        else:
            assert execute(env, command)["output"].strip() == base64.b64encode(data).decode()
            assert execute(env, command + "; echo extra")["output"] == messages.WITNESS_CALL_CHANGED
            assert execute(env, f"base64 < '{core.base}/work/other.{extension}'")["output"] == messages.WITNESS_CALL_CHANGED


def test_a_tilde_read_uses_only_the_exact_home_probe(core, monkeypatch):
    from hands import client

    (core.home / "work" / "notes.txt").write_bytes(b"home note\n")
    core.show("read_file", {"path": "~/work/notes.txt"})
    commands = []
    execute = environment.HandsEnvironment.execute

    def capture(env, command, cwd="", **kwargs):
        commands.append(command)
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", capture)
    # The paired device reports its own HOME, as a real device does.
    monkeypatch.setenv("HOME", core.base)
    result = core.files.read_file_tool("~/work/notes.txt", task_id=TASK)
    assert "home note" in result, (result, commands)
    assert "echo $HOME" in commands
    assert client._REFUSED_CALLS == {}
    env = core.files._get_file_ops(TASK).env
    assert execute(env, "echo $HOME; echo extra")["output"] == messages.WITNESS_CALL_CHANGED


def test_bare_rg_zero_match_hint_matcher_requires_the_shown_search(core, monkeypatch):
    import shutil

    executable = shutil.which("rg")
    if executable is None:
        pytest.skip("ripgrep is required to exercise the cached rg zero-match hint")
    (core.home / "work" / "notes.txt").write_bytes(b"some text\n")
    args = {"path": f"{core.base}/work", "pattern": "ABSENT[0]", "file_glob": "*.txt"}
    core.show("search_files", args)
    ops = core.files._get_file_ops(TASK)
    ops._rg_resolution_cache["rg"] = "rg"
    execute = environment.HandsEnvironment.execute
    hints = []
    commands = []

    def capture(env, command, cwd="", **kwargs):
        result = execute(env, command, cwd, **kwargs)
        commands.append((command, result))
        if "--count-matches" in command:
            assert messages.WITNESS_CALL_CHANGED not in result["output"], (command, result)
            hints.append(command)
        return result

    monkeypatch.setattr(environment.HandsEnvironment, "execute", capture)
    result = core.files.search_tool(**args, task_id=TASK)
    assert '"total_count": 0' in result and '"error"' not in result, result
    assert len(hints) == 3, "\n".join(repr(item) for item in commands)
    for command in hints:
        assert execute(ops.env, command + "; echo extra", timeout=30)["output"] == messages.WITNESS_CALL_CHANGED
        assert execute(ops.env, command.replace("/work'", "/other'"), timeout=30)["output"] == messages.WITNESS_CALL_CHANGED
        for other in ("relative/rg", environment.device_path(executable)):
            assert execute(ops.env, command.replace("rg ", f"'{other}' ", 1), timeout=30)["output"] == messages.WITNESS_CALL_CHANGED


@pytest.mark.parametrize("changed", ["folder", "log", "exit", "pid"])
def test_background_destinations_are_canonical_before_any_job(core, monkeypatch, changed):
    import shlex
    from hands import client

    core.show("terminal", {"command": "echo bg", "background": True})
    env = core.files._get_file_ops(TASK).env
    folder = env.get_temp_dir().rstrip("/") or "/"
    paths = {ext: f"{folder}/hermes_bg_proc_123456789abc.{ext}" for ext in ("log", "exit", "pid")}
    if changed == "folder":
        folder += "/other"
    else:
        paths[changed] = f"{folder}/other/hermes_bg_proc_123456789abc.{changed}"
    q = shlex.quote
    command = (
        f"mkdir -p {q(folder)} && ( nohup bash -lc {q('echo bg')} > {q(paths['log'])} 2>&1; "
        f"rc=$?; printf '%s\\n' \"$rc\" > {q(paths['exit'])} ) & echo $! > {q(paths['pid'])} && cat {q(paths['pid'])}"
    )
    monkeypatch.setattr(client, "start_job", lambda *a, **k: pytest.fail("an altered launcher queued a job"))
    result = env.execute(command, cwd="~")
    assert result["output"] == messages.WITNESS_CALL_CHANGED, result


@pytest.mark.parametrize("prefix,ending", [(b"", b"\n"), (b"\xef\xbb\xbf", b"\r\n"), (b"", b"")])
def test_replace_all_writes_every_exact_match_and_only_the_expected_bytes(core, prefix, ending):
    notes = core.home / "work" / "notes.txt"
    path = f"{core.base}/work/notes.txt"
    separator = ending or b" "
    original = prefix + b"one" + separator + b"one" + ending
    notes.write_bytes(original)
    args = {"mode": "replace", "path": path, "old_string": "one", "new_string": "two", "replace_all": True}
    core.show("patch", args)
    result = core.files.patch_tool(**args, task_id=TASK)
    assert messages.WITNESS_PATCH_NOT_EXACT not in result, result
    assert notes.read_bytes() == prefix + b"two" + separator + b"two" + ending, result
    for old in (" one ", "absent"):
        notes.write_bytes(original)
        changed = {**args, "old_string": old}
        core.show("patch", changed)
        core.files.patch_tool(**changed, task_id=TASK)
        assert notes.read_bytes() == original
    notes.write_bytes(original)
    core.show("patch", {**args, "replace_all": False})
    core.files.patch_tool(**args, task_id=TASK)
    assert notes.read_bytes() == original
    core.show("patch", args)
    core.files.patch_tool(**{**args, "new_string": "other"}, task_id=TASK)
    assert notes.read_bytes() == original
