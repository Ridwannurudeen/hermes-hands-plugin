"""Path-aware credential rules through registered core handlers and the Bash device."""

import json

import pytest

pytest.importorskip("tools.environments.base")

from hands import messages  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401


@pytest.mark.parametrize("content", [
    "token = abc123def456", "password = hunter2",
    "Authorization = Bearer abc123def456", 'password = "two words"',
    "token = abc.def",
])
@pytest.mark.parametrize("extension", [".env", ".ini", ".yaml", ".txt", ""])
@pytest.mark.parametrize("tool", ["write_file", "patch"])
def test_spaced_credentials_in_data_files_are_refused(dispatch, content, extension, tool):
    d = dispatch
    target = d.home / "work" / ("config" + extension)
    target.write_bytes(b"old")
    args = {"path": f"{d.base}/work/config{extension}"}
    args.update({"content": content} if tool == "write_file" else {"old_string": "old", "new_string": content})
    result = d.invoke(tool, args)
    assert messages.WITNESS_SECRET_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []
    assert target.read_bytes() == b"old"


@pytest.mark.parametrize("content", [
    "token = abc123def456", "password = hunter2",
    "Authorization = Bearer abc123def456", 'password = "two words"',
])
def test_spaced_credentials_without_file_context_are_refused(dispatch, content):
    d = dispatch
    result = d.invoke("terminal", {"command": "echo '" + content + "'", "timeout": 5})
    assert messages.WITNESS_SECRET_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("extension", [".py", ".js"])
@pytest.mark.parametrize("content", [
    "token = credentials", "password = hunter2", "token = abc123def456",
    "token = config.token", "token = get_token()", 'token = config["token"]',
    "token = None", "password = null", "token = nil", "password = true",
    "token = false", "password = True", "token = False", "token = -2.5",
    'token = ""', "token = ''", 'token = "..."', 'token = "xxx"',
    'token = "<token>"', 'token = "${VAR}"', 'token = "$VAR"',
    'token = "" # ordinary comment', "token = 0x1234567890abcdef1234567890",
    'token = get_token(config["token"])', 'token = config[get_name("token")]',
    "token = 1_000", 'token = get_config()["token"].value',
])
def test_source_identifiers_expressions_and_placeholders_reach_exact_write(dispatch, monkeypatch, extension, content):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    target = d.home / "work" / ("source" + extension)
    result = d.invoke("write_file", {"path": f"{d.base}/work/source{extension}", "content": content})
    assert not json.loads(result).get("error"), result
    assert len(d.cards) == len(d.answers) == 1 and d.jobs
    assert target.read_bytes() == content.encode()
    assert any(job.get("stdin") == content for job in d.jobs)


@pytest.mark.parametrize("extension", [".py", ".js"])
@pytest.mark.parametrize("content", [
    "Authorization = Bearer abc123def456", 'password = "two words"',
    'password = "hunter2"', 'token = "abc123def456"',
    "token = abcdefghijklmnopqrst", "token = sk-short", "token = ghp_short",
    'password = "" + "hunter2"', 'password = "" or "hunter2"',
    'password = f"hunter2"', "password = `hunter2`",
    'password = "" "hunter2"',
    'password = ("hunter2")', 'password = x + "hunter2"', "password = ['hunter2']",
    "token = xoxc-short",
    'password = config.token + "hunter2"', 'password = get_token() + "hunter2"',
    'password = config.token or "hunter2"', 'password = get_token() or "hunter2"',
    'password = config["token"] + "hunter2"', 'password = 1 + "hunter2"',
    'password = get_token(), "hunter2"', 'password = credentials, "hunter2"',
    'password = "", "hunter2"',
    'password = get_token(# )\n) + "hunter2"',
])
def test_source_literals_are_still_refused(dispatch, monkeypatch, extension, content):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    result = d.invoke("write_file", {"path": f"{d.base}/work/source{extension}", "content": content})
    assert messages.WITNESS_SECRET_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("extension,refused", [(".py", True), (".js", False)])
def test_slash_comments_use_the_source_file_context(dispatch, monkeypatch, extension, refused):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    content = 'password = 2 // 1 + "hunter2"'
    result = d.invoke("write_file", {"path": f"{d.base}/work/source{extension}", "content": content})
    if refused:
        assert messages.WITNESS_SECRET_BLOCKED in result, result
        assert d.cards == [] and d.answers == [] and d.jobs == []
    else:
        assert not json.loads(result).get("error"), result
        assert len(d.cards) == len(d.answers) == 1 and d.jobs
        assert (d.home / "work" / ("source" + extension)).read_bytes() == content.encode()


@pytest.mark.parametrize("content,refused", [
    ('password = get_token(// )\n) + "hunter2"', True),
    ('password = get_token(/* ) */) + "hunter2"', True),
    ('password = get_token(/* ) */)', False),
    ('password = get_token() // ordinary comment', False),
    ('password = get_token() /* ordinary comment */', False),
])
def test_source_call_comments_cannot_hide_a_literal_fallback(dispatch, monkeypatch, content, refused):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    result = d.invoke("write_file", {"path": f"{d.base}/work/source.js", "content": content})
    if refused:
        assert messages.WITNESS_SECRET_BLOCKED in result, result
        assert d.cards == [] and d.answers == [] and d.jobs == []
    else:
        assert not json.loads(result).get("error"), result
        assert len(d.cards) == len(d.answers) == 1 and d.jobs
        assert (d.home / "work" / "source.js").read_bytes() == content.encode()


@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("content", [
    "token = (get_token())", "token = await get_token()",
    "token = ((get_token()))", "token = await (get_token())",
    "token = (get_token())\ncount = 1", "token = await get_token()\ncount = 1",
    "token = (get_token()); count = 1", "token = await get_token(); count = 1",
    "configured = connect(token=(get_token()))", "configured = connect(token=await get_token())",
])
def test_grouped_and_awaited_calls_keep_approved_bytes(dispatch, monkeypatch, tool, content):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    target = d.home / "work" / "source.py"
    target.write_bytes(b"old")
    args = {"path": f"{d.base}/work/source.py"}
    args.update({"content": content} if tool == "write_file" else {"old_string": "old", "new_string": content})
    result = d.invoke(tool, args)
    assert not json.loads(result).get("error"), result
    assert len(d.cards) == len(d.answers) == 1 and d.jobs
    assert target.read_bytes() == content.encode()
    assert any(job.get("stdin") == content for job in d.jobs)


@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("content", [
    'password = ("hunter2")', 'password = (("hunter2"))',
    'password = f"hunter2"', 'password = (f"hunter2")',
    'password = await "hunter2"', 'password = (get_token()) + "hunter2"',
    'password = await get_token() or "hunter2"',
    'password = (get_token(), "hunter2")',
    'token = await get_token(await other())', 'token = (yield get_token())',
    'password = (get_token()\nor "hunter2")',
    'password = (get_token() # comment\nor "hunter2")',
    'password = (config.token\n+ "hunter2")',
])
def test_grouped_and_awaited_lookalikes_stay_refused(dispatch, monkeypatch, tool, content):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    target = d.home / "work" / "source.py"
    target.write_bytes(b"old")
    args = {"path": f"{d.base}/work/source.py"}
    args.update({"content": content} if tool == "write_file" else {"old_string": "old", "new_string": content})
    result = d.invoke(tool, args)
    assert messages.WITNESS_SECRET_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []
    assert target.read_bytes() == b"old"


@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("extension,content,whole_source", [
    (".py", "password=True", True),
    (".py", "password=hunter2", True),
    (".py", 'config = """[login]\npassword=hunter2\n"""', False),
    (".py", "[login settings]\npassword=hunter2", False),
    (".py", "def broken(:\n password=True", False),
    (".js", "password=True", False),
    (".txt", "password=True", False),
])
def test_spacing_hint_requires_a_whole_python_assignment(dispatch, tool, extension, content, whole_source):
    d = dispatch
    target = d.home / "work" / ("source" + extension)
    target.write_bytes(b"old")
    args = {"path": f"{d.base}/work/source{extension}"}
    args.update({"content": content} if tool == "write_file" else {"old_string": "old", "new_string": content})
    result = d.invoke(tool, args)
    assert messages.WITNESS_SECRET_HIDDEN in result, result
    assert ("spaces around =" in result) == (tool == "write_file" and whole_source)
    assert d.cards == [] and d.answers == [] and d.jobs == []
    assert target.read_bytes() == b"old"


def test_patch_inside_python_configuration_string_does_not_suggest_retry(dispatch):
    d = dispatch
    target = d.home / "work" / "source.py"
    original = b'config = """[login]\npassword = default\n"""'
    target.write_bytes(original)
    result = d.invoke("patch", {
        "path": f"{d.base}/work/source.py", "old_string": "password = default",
        "new_string": "password=hunter2",
    })
    assert messages.WITNESS_SECRET_HIDDEN in result, result
    assert "spaces around =" not in result
    assert d.cards == [] and d.answers == [] and d.jobs == []
    assert target.read_bytes() == original


@pytest.mark.parametrize("content,expected", [
    ("password=True", True),
    ("options = connect(\n    password=True\n)", True),
    ("# password=True", False),
    ('note = "password=True"', False),
    ('config = """[login]\npassword=True\n"""', False),
    ("[login settings]\npassword=True", False),
    ("def connect(password=True):\n pass", False),
    ("password: bool=True", False),
    ("password=True\n# password=True", False),
    ("caf\u00e9 = 1; password=True", True),
])
def test_hint_assignment_must_be_an_actual_python_ast_node(content, expected):
    from hands import witness

    assert witness._python_source_assignments(content) is expected
