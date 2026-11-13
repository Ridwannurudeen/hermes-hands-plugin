import contextvars
import re

import pytest

from hands import client, witness
from hands_fakes import PLUGIN_DIR

SKILL_MD = PLUGIN_DIR / "skills" / "hands" / "SKILL.md"
TITLES = ("One site or app fails", "Printer stuck", "Slow PC", "Disk full", "Program frozen")
DEVICE = {
    "name": "laptop",
    "device_id": "device-id",
    "witness": True,
    "session_state": "active",
    "instance": "serve-1",
    "capabilities": ["witness-v1"],
}


def _source() -> str:
    return SKILL_MD.read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def _section(title: str) -> str:
    match = re.search(
        rf"^### {re.escape(title)} \(Windows only\)\n(.*?)(?=^### |\Z)", _source(), re.M | re.S
    )
    assert match is not None, title
    return " ".join(match.group(1).split())


def _normalized() -> str:
    return " ".join(_source().split())


@pytest.mark.parametrize("title", TITLES)
def test_each_playbook_asks_for_the_helpers_approval_before_its_terminal_call(title):
    section = _section(title)
    approval = section.find("Ask for the helper's approval")
    call = section.find("**Helper terminal call.**")
    assert 0 <= approval < call, title
    assert not re.search(
        r"\b(?:do not|don't|never|no need to|without)\b\W+(?:\w+\W+){0,3}?helper's approval",
        section,
        re.I,
    )


OUTCOMES = {
    "One site or app fails": "Report `fixed` only if she says it works; report `not fixed` if the recheck shows it still fails, or `unknown` if verification is unavailable.",
    "Printer stuck": "Report `fixed` only if the document printed; report `not fixed` if it remains stuck, or `unknown` if verification is unavailable.",
    "Slow PC": "If the setting is off but she sees no change, report `unknown`",
    "Disk full": "Report `fixed` only if free space went up and the low space warning is gone. Report `not fixed` if the measured symptom remains, or `unknown` if verification is unavailable.",
    "Program frozen": "Report `fixed` only if the app opens and responds; report `not fixed` if the symptom remains, or `unknown` if verification is unavailable.",
}


@pytest.mark.parametrize("title", TITLES)
def test_each_playbook_keeps_its_exact_outcome_rule(title):
    assert OUTCOMES[title] in _section(title)


def test_slow_pc_has_one_outcome_rule_when_the_change_shows_no_effect():
    section = _section("Slow PC")
    assert "report `not fixed` if it remains" not in section
    assert "If no effect can be verified, report unknown" not in section
    assert "Report `not fixed` only if the setting is still on after the change" in section


@pytest.fixture
def gate(monkeypatch):
    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("r3b1_skill", default=None))
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    return lambda command: witness.pre_tool_call(object(), "terminal", {"command": command})


def test_every_playbook_command_and_its_undo_form_is_held_for_approval_by_the_real_hook(gate):
    source = _source()
    commands = [
        line
        for language, block in re.findall(r"^```([^\n]*)\n(.*?)\n```", source, re.M | re.S)
        for line in block.splitlines()
        if language == "bash"
    ]
    assert len(commands) == 7
    normalized = _normalized()
    assert "restoring the recorded 1 with the same command and `/d 1`" in normalized
    assert "with `/U` in place of `/C`" in normalized
    [reg_add] = [command for command in commands if "reg.exe add" in command]
    [compact] = [command for command in commands if "compact.exe /C" in command]
    commands += [reg_add.replace("/d 0", "/d 1"), compact.replace("/C", "/U", 1)]
    for command in commands:
        decision = gate(command)
        assert decision is not None and decision["action"] == "approve", (command, decision)


def test_playbooks_say_the_hook_and_the_screen_line_exist_only_in_a_witness_session():
    normalized = _normalized()
    assert "only in a witness session" in normalized
    assert (
        "Outside one, a terminal call runs at once and she sees nothing in Hermes Hands"
        in normalized
    )
    assert "treat every repair as if it runs the moment you submit it" in normalized
    assert "wait for its approval, and execute only after approval" not in normalized
    assert "execute only after approval" not in normalized.casefold()
    for title in TITLES:
        assert "**What she sees:** In a witness session," in _section(title), title


def test_frozen_app_matches_only_a_single_confirmed_file_name_and_spares_the_shell():
    section = _section("Program frozen")
    assert "Plain `tasklist` shows only program file names and process numbers" in section
    assert "Never guess from a name" not in section
    assert "Never end explorer.exe" in section
    assert "the program that runs the Hermes Hands window" in section
    assert "exactly one row has the program file name" in section


def test_dns_repair_names_evidence_the_person_can_report_and_calls_it_a_guess():
    section = _section("One site or app fails")
    assert "observed DNS failure with working IP reachability" not in section
    assert "DNS_PROBE_FINISHED_NXDOMAIN" in section
    assert "Tell the helper the repair is a guess" in section
    assert "the only repair is then the manual close and reopen below" in section


def test_witness_sessions_prefer_short_home_paths():
    normalized = _normalized()
    assert "In a witness session, prefer short `~/...` paths" in normalized
    assert "refused, not shortened" in normalized


def test_witness_rules_name_the_blocked_symbols_persistence_and_other_plugin_remedy():
    normalized = _normalized()
    assert "anywhere in a command, even inside quotes" in normalized
    assert "because it would outlast the 30 minute session" in normalized
    assert "The list is not complete." in normalized
    assert "including commands that can start other programs, waits for the helper" in normalized
    assert "the device also refuses a command that is not the one the helper approved" in normalized
    assert "`hermes plugins disable <name>` for a plugin" not in normalized
    assert "If a refusal names an argument that is too long, shorten that argument" in normalized
    assert "prefer short `~/...` paths in file tools and commands" not in normalized


def test_disk_full_names_safe_folders_and_the_blocked_path_symbols(gate):
    section = _section("Disk full")
    assert (
        "Never compress the Windows folder, Program Files, AppData, her whole user folder or a OneDrive synced folder"
        in section
    )
    assert "Do not run `compact.exe /CompactOS` or delete anything" in section
    assert "use the manual steps below for that folder" in section
    for folder in ("Archive [2019]", "Tom & Ann", "Old~1", "Notes #2", "Wow!", "100%"):
        command = rf'MSYS_NO_PATHCONV=1 compact.exe /C /S:"C:\Users\Example\{folder}"'
        assert gate(command)["action"] == "block", folder


def test_witness_steps_each_need_their_own_approval_without_session_or_always_buttons():
    normalized = _normalized()
    assert "In a witness session each step needs its own approval." in normalized
    assert "do not carry over to later steps" in normalized
    assert "do not suggest those buttons" in normalized
