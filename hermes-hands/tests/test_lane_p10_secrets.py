"""Cheap secret shapes and core-redactor differential checks for witness cards."""

import pytest

from hands import messages, witness
from test_witness_hardening import DEVICE


SECRETS = [
    "pass=abc",
    "pwd=abc",
    "mysql -p hunter2",
    "mysql -phunter2",
    "mysql --host db -p hunter2",
    "mariadb -phunter2",
    "sshpass -p hunter2 ssh h",
    "sshpass -phunter2 ssh h",
    "curl -u bob:hunter2 https://x",
    "curl -ubob:hunter2 https://x",
    "curl --user bob:hunter2 https://x",
    "service --password hunter2",
    "service --password=hunter2",
    "ya29." + "a" * 30,
    "https://hooks.slack.com/services/T123/B456/abcdef",
    "AccountKey=abcdef==",
    "X-Amz-Signature=abcdef123456",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Bearer [abc]",
]


@pytest.mark.parametrize("text", SECRETS)
def test_cheap_secret_shapes_are_refused(text, monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    assert witness._SECRET_HINT.search(text) is not None
    assert witness._contains_secret(text)
    expected = messages.WITNESS_SECRET_HIDDEN if text.startswith(("service --password", "AccountKey=")) else messages.WITNESS_SECRET_BLOCKED
    for prefix in ("", "ordinary notes " * 30):
        assert witness.pre_tool_call(
            object(), "write_file", {"path": "/notes.txt", "content": prefix + text}
        ) == {"action": "block", "message": expected}


@pytest.mark.parametrize("command", SECRETS[2:13])
def test_command_passwords_are_refused_before_approval(command, monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    expected = messages.WITNESS_SECRET_HIDDEN if command.startswith("service --password") else messages.WITNESS_SECRET_BLOCKED
    assert witness.pre_tool_call(object(), "terminal", {"command": command}) == {
        "action": "block", "message": expected,
    }


@pytest.mark.parametrize("command", [
    "ls -p", "ls -p /tmp", "mkdir -p dir", "cat pass_through.py",
    "mysql -p", "mysql -P 3306", "mysql -p --host db", "curl -u bob https://x",
])
def test_non_password_flags_and_ordinary_paths_are_allowed(command, monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    assert not witness._contains_secret(command)
    assert witness.pre_tool_call(object(), "terminal", {"command": command})["action"] == "approve"


def test_secret_word_inside_path_is_not_a_secret():
    assert not witness._contains_secret("/home/sam/pass_through.py")


@pytest.mark.parametrize("text", SECRETS + [
    "BRAVE_API_KEY=opaquecredentialvalue123456789",
    "postgresql://user:hunter2@localhost/db",
    "hf_" + "a" * 30,
    "ordinary notes",
])
def test_every_core_redaction_is_refused(text):
    redact = pytest.importorskip("agent.redact").redact_sensitive_text
    for value in (text, f"command={text}", f'content="{text}"'):
        if redact(value, force=True) != value:
            assert witness._contains_secret(value)
