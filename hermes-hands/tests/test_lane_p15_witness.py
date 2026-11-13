"""Source expressions and quoted data keep their approved bytes through real dispatch."""

import json

import pytest

pytest.importorskip("tools.environments.base")

from hands import messages, witness  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401


@pytest.mark.parametrize("content", [
    "token = get_token()", "token = 1", "token = -2.5",
    "token = None", "token = 0", "token = config.token", "password = False",
    "password = null", "token = True", "token = False", "token = credentials",
    "token = config.session_token", "token = os.environXYZ123",
    "token = process.envXYZ123.TOKEN", 'token = os.getenv("TOKEN")',
    'token = os.environ["TOKEN"]', "token = process.env.TOKEN",
    'token = ""',
])
def test_source_expression_reaches_registered_write_unchanged(dispatch, monkeypatch, content):
    from agent.redact import redact_sensitive_text

    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    assert redact_sensitive_text(content, force=True) == content
    result = d.invoke("write_file", {"path": f"{d.base}/work/source.py", "content": content})
    assert not json.loads(result).get("error"), result
    assert len(d.cards) == 1 and d.answers and d.jobs
    assert (d.home / "work" / "source.py").read_bytes() == content.encode()
    assert any(job.get("stdin") == content for job in d.jobs), d.jobs


@pytest.mark.parametrize("content", [
    'password = "hunter2"', 'token = "ghp_' + "a" * 36 + '"',
    'password = r"hunter2"', 'password = """hunter2"""',
    "token=k9XjN2qV6rY4sW8aB3cD7eF1gH5iL0mP",
    "Bearer " + "a" * 30, "-----BEGIN PRIVATE KEY-----", "mysql -p hunter2",
    "https://user:hunter2@example.com",
    'token = "hello world"', 'password = "not a credential"',
])
@pytest.mark.parametrize("prefix", ["", "ordinary notes " * 40])
def test_complete_credential_scan_blocks_before_any_job(dispatch, content, prefix):
    d = dispatch
    result = d.invoke("write_file", {"path": f"{d.base}/work/source.txt", "content": prefix + content})
    assert messages.WITNESS_SECRET_BLOCKED in result
    assert d.cards == [] and d.jobs == []
    assert not (d.home / "work" / "source.txt").exists()


@pytest.mark.parametrize("command", [
    "git commit -m 'start the server'", "echo 'rm -rf x'", "echo 'start the server'",
    "git commit -m 'bash repair.sh'", "echo 'crontab notes.txt'",
])
def test_ordinary_terminal_data_is_not_a_nested_command(dispatch, command):
    d = dispatch
    assert d.base in d.call("terminal", {"command": "pwd", "timeout": 5})
    d.jobs.clear()
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED not in result, result
    assert d.cards[0].startswith("Hands witness approval required: tool=terminal;")
    assert "command=" + command + "; timeout=5" in d.cards[0]
    assert d.cards[1:] == (["recursive delete"] if command == "echo 'rm -rf x'" else [])
    assert len(d.answers) == len(d.cards) and len(d.jobs) == 1
    assert command.replace("'", "'\\''") in d.jobs[0]["script"], d.jobs


@pytest.mark.parametrize("command", [
    "sh -c 'start the server'", "bash -c 'rm -rf x'", "env bash repair.sh",
    "xargs bash repair.sh", "find . -exec bash repair.sh +",
    "ssh host 'bash repair.sh'", "docker exec container bash repair.sh",
    "podman exec container bash repair.sh", "make CMD='bash repair.sh'",
])
def test_actual_command_carriers_never_reach_a_job(dispatch, command):
    d = dispatch
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED in result, result
    assert d.cards == [] and d.jobs == []


@pytest.mark.parametrize("content", [
    "pwd=abc", "pass=abc", "PASSWORD=hunter2", "X-Amz-Signature=abcdef123456",
    "token=abc.def", "token=None", "token=0", "token=config.token",
])
def test_unspaced_credential_assignments_are_refused_before_any_job(dispatch, content):
    d = dispatch
    result = d.invoke("write_file", {"path": f"{d.base}/work/source.txt", "content": content})
    assert messages.WITNESS_SECRET_BLOCKED in result
    assert d.cards == [] and d.jobs == []
    assert not (d.home / "work" / "source.txt").exists()


def test_hands_literal_refusal_has_precise_message():
    from agent.redact import redact_sensitive_text

    content = 'password = "hunter2"'
    assert redact_sensitive_text(content, force=True) == content
    assert witness._contains_secret(content)
    assert messages.WITNESS_SECRET_BLOCKED == (
        "Hermes Hands blocked this call because an argument looks like a secret, such as a key, "
        "token or password. Do not send secrets to the device."
    )


def test_documented_core_masked_annotation_is_refused_before_any_job(dispatch):
    from agent.redact import redact_sensitive_text

    content = "token: Optional[str]"
    assert redact_sensitive_text(content, force=True) == "token: ***"
    d = dispatch
    result = d.invoke("write_file", {"path": f"{d.base}/work/source.txt", "content": content})
    assert "approval card would hide" in result
    assert d.cards == [] and d.jobs == []
    assert not (d.home / "work" / "source.txt").exists()


@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("extension", [".py", ".js"])
@pytest.mark.parametrize("content", [
    "def connect(host, password=None, token=None):",
    "client = Client(token=token, api_key=api_key)",
    "api_key=os.getenv('API_KEY')", 'token=""',
    "token=0", "token=config.token", 'token=config["token"]',
    "client = Client(token = token, api_key = api_key)",
    "password=True", "password = True",
])
def test_unspaced_source_reaches_registered_file_handler(dispatch, monkeypatch, tool, extension, content):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    target = d.home / "work" / ("source" + extension)
    target.write_bytes(b"old")
    args = {"path": f"{d.base}/work/source{extension}"}
    args.update({"content": content} if tool == "write_file" else {"old_string": "old", "new_string": content})
    from agent.redact import redact_sensitive_text

    result = d.invoke(tool, args)
    if content in {
        "client = Client(token=token, api_key=api_key)",
        "client = Client(token = token, api_key = api_key)",
        "password=True",
    }:
        assert redact_sensitive_text(content, force=True) != content
        assert messages.WITNESS_SECRET_HIDDEN in result
        assert "approval card would hide" in result
        assert ("spaces around =" in result) == (content == "password=True" and tool == "write_file" and extension == ".py")
        assert d.cards == [] and d.answers == [] and d.jobs == []
        assert target.read_bytes() == b"old"
    else:
        assert redact_sensitive_text(content, force=True) == content
        assert not json.loads(result).get("error"), result
        assert len(d.cards) == len(d.answers) == 1 and d.jobs
        assert target.read_bytes() == content.encode()
        assert any(job.get("stdin") == content for job in d.jobs), d.jobs


@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("extension", [".py", ".js", ".env", ".txt", ".sh"])
@pytest.mark.parametrize("content", [
    'def connect(host, password="hunter2"):', 'api_key="abc123def456"',
    "token=sk-" + "a" * 40, "password=hunter2xyz",
    "token=os.environXYZ123", "token=process.envXYZ123",
    "token=process.envXYZ123.TOKEN", "token=os.environXYZ123.TOKEN",
    "token=os.getenvXYZ123.TOKEN", "token=os.environbXYZ123.TOKEN",
    "token=os.environb.TOKEN", "token=os.getenv.TOKEN", "token=process.env",
    'token=get_token(), "hunter2"', 'token=credentials, "hunter2"',
    'token="", "hunter2"', "token=k9XjN2qV6rY4sW8aB3cD7eF1gH5iL0mP",
])
def test_unspaced_credentials_refused_by_registered_file_handler(dispatch, tool, extension, content):
    d = dispatch
    target = d.home / "work" / ("source" + extension)
    target.write_bytes(b"old")
    args = {"path": f"{d.base}/work/source{extension}"}
    args.update({"content": content} if tool == "write_file" else {"old_string": "old", "new_string": content})
    result = d.invoke(tool, args)
    assert messages.WITNESS_SECRET_BLOCKED in result or messages.WITNESS_SECRET_HIDDEN in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []
    assert target.read_bytes() == b"old"


@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("extension", [".env", ".txt", ".unknown", "", ".sh", ".bash", ".zsh"])
@pytest.mark.parametrize("content", [
    "def connect(host, password=None, token=None):",
    "client = Client(token=token, api_key=api_key)",
    "api_key=os.getenv('API_KEY')", 'token=""', "PASSWORD=hunter2",
])
def test_unspaced_data_and_shell_assignments_stay_refused(dispatch, tool, extension, content):
    d = dispatch
    target = d.home / "work" / ("source" + extension)
    target.write_bytes(b"old")
    args = {"path": f"{d.base}/work/source{extension}"}
    args.update({"content": content} if tool == "write_file" else {"old_string": "old", "new_string": content})
    result = d.invoke(tool, args)
    assert messages.WITNESS_SECRET_BLOCKED in result or messages.WITNESS_SECRET_HIDDEN in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []
    assert target.read_bytes() == b"old"


@pytest.mark.parametrize("content", [
    "def connect(host, password=None, token=None):",
    "client = Client(token=token, api_key=api_key)",
    "api_key=os.getenv('API_KEY')", 'token=""',
    'def connect(host, password="hunter2"):', 'api_key="abc123def456"',
    "token=sk-" + "a" * 40, "password=hunter2xyz", "PASSWORD=hunter2",
])
def test_unspaced_terminal_arguments_stay_refused(dispatch, content):
    import shlex

    d = dispatch
    result = d.invoke("terminal", {"command": "echo " + shlex.quote(content), "timeout": 5})
    assert any(message in result for message in (
        messages.WITNESS_SECRET_BLOCKED, messages.WITNESS_SECRET_HIDDEN, messages.WITNESS_COMMAND_BLOCKED,
    )), result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("content", [
    "token=nil", "token=true", "token=false", "password=True", "token=False",
    "token=-2.5", "token=get_token()", "token=settings.api_key", "self.token=token",
    'token=os.environ["TOKEN"]', 'token=os.environ.get("TOKEN")',
    'token=process.env.TOKEN', 'token=process.env["TOKEN"]',
    "token=''", 'token="..."', 'token="xxx"', 'token="<token>"',
    'token="${VAR}"', 'token="$VAR"',
])
def test_unspaced_source_expression_spellings(content):
    if content == "password=True":
        assert messages.WITNESS_SECRET_HIDDEN in witness._secret_problem(content, source=True)
    else:
        assert not witness._contains_secret(content, source=True)


@pytest.mark.parametrize("extension", [".js", ".ts"])
@pytest.mark.parametrize("tool", ["write_file", "patch"])
@pytest.mark.parametrize("content", [
    "const options = {token:token, api_key:api_key};",
    'const options = {token:"", password:null};',
])
def test_source_object_literals_reach_registered_handler(dispatch, monkeypatch, extension, tool, content):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    target = d.home / "work" / ("source" + extension)
    target.write_bytes(b"old")
    args = {"path": f"{d.base}/work/source{extension}"}
    args.update({"content": content} if tool == "write_file" else {"old_string": "old", "new_string": content})
    result = d.invoke(tool, args)
    assert not json.loads(result).get("error"), result
    assert len(d.cards) == len(d.answers) == 1 and d.jobs
    assert target.read_bytes() == content.encode()


@pytest.mark.parametrize("content", [
    "token=ghp_a", "token=github_pat_a", "token=xoxb-a",
    "token=AKIA1", "token=AIza1", "token=ya29.a",
])
def test_unspaced_source_keeps_short_known_token_prefix_refusals(content):
    assert witness._contains_secret(content, source=True)


@pytest.mark.parametrize("source,card,unspaced,expected_hint", [
    (True, False, True, True), (False, False, True, False),
    (True, True, True, False), (True, False, False, False),
])
def test_core_masked_spacing_hint_requires_source_context(source, card, unspaced, expected_hint):
    problem = witness._secret_problem("password=True", source=source, card=card, unspaced=unspaced, spacing_hint=True)
    assert messages.WITNESS_SECRET_HIDDEN in problem
    assert ("spaces around =" in problem) == expected_hint


def test_core_masked_spacing_hint_checks_forced_redaction_at_call_time(monkeypatch):
    from agent import redact

    original = redact.redact_sensitive_text
    calls = []

    def mask_spaced(text, *, force=False):
        calls.append((text, force))
        return "password=***" if text == "password = True" else original(text, force=force)

    monkeypatch.setattr(redact, "redact_sensitive_text", mask_spaced)
    assert witness._secret_problem("password=True", source=True, spacing_hint=True) == messages.WITNESS_SECRET_HIDDEN
    assert ("password = True", True) in calls


def test_spacing_hint_does_not_recommend_a_refused_literal():
    content = 'token="os.getenv(TOKEN) + literal"'
    problem = witness._secret_problem(content, source=True, spacing_hint=True)
    assert problem == messages.WITNESS_SECRET_HIDDEN
    assert "spaces around =" not in problem
