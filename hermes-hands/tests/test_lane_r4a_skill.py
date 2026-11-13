"""Round-4 SKILL.md claims checked against the real witness gate."""

import re

import pytest

from hands import messages, witness
from hands_fakes import PLUGIN_DIR
from test_lane_r3a_witness import DEVICE, fresh_tool_session  # noqa: F401  (fixture)

SKILL_MD = PLUGIN_DIR / "skills" / "hands" / "SKILL.md"
SCREENSHOT = "/home/someuser/.hermes/cache/hermes-hands/0b4f9c6e-8a51-4d2e-9a43-5c1f2e7d9b10.png"


def _normalized() -> str:
    return " ".join(SKILL_MD.read_text(encoding="utf-8-sig").split())


@pytest.fixture
def gate(monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: {**DEVICE, "name": "office-pc-02"})
    return lambda tool, args: witness.pre_tool_call(object(), tool, args)


def test_the_skill_keeps_the_witness_screenshot_question_short_enough_to_approve(gate):
    """r3-relay-skill-4: a normal-length vision_analyze question is refused as too long."""
    text = _normalized()
    match = re.search(r"keep the `vision_analyze` question short, such as \"([^\"]+)\"", text)
    assert match, "the Screenshots section must say how short the question must be"
    example = match.group(1)
    assert (
        gate("vision_analyze", {"image_path": SCREENSHOT, "question": example})["action"]
        == "approve"
    )
    long_question = "Describe what is on the screen, including any error messages, dialog boxes or window titles."
    assert (
        gate("vision_analyze", {"image_path": SCREENSHOT, "question": long_question})["action"]
        == "block"
    )
    limit = int(
        re.search(r"under (\d+) characters", text[match.start() - 300 : match.end() + 300]).group(1)
    )
    assert (
        gate("vision_analyze", {"image_path": SCREENSHOT, "question": "q" * (limit - 1)})["action"]
        == "approve"
    )


def test_the_skill_lists_every_symbol_the_gate_refuses():
    """r3-relay-skill-5: the lists must match messages.WITNESS_COMMAND_BLOCKED and witness._SHELL_META."""
    rules = (
        _normalized()
        .split("During a witness session Hermes Hands blocks:", 1)[1]
        .split("The list is not complete", 1)[0]
    )
    disk = _normalized().split("### Disk full (Windows only)", 1)[1].split("###", 1)[0]
    for symbol in witness._SHELL_META:
        assert f"`{symbol}`" in rules or (symbol == "`" and "backtick" in rules), symbol
        assert f"`{symbol}`" in disk or (symbol == "`" and "backtick" in disk), symbol


@pytest.mark.parametrize("folder", ["Autostart", "LaunchAgents", "LaunchDaemons", "profile.d"])
def test_the_folder_names_the_skill_sends_to_the_manual_steps_are_refused(gate, folder):
    disk = _normalized().split("### Disk full (Windows only)", 1)[1].split("###", 1)[0]
    assert folder in disk
    command = rf'MSYS_NO_PATHCONV=1 compact.exe /C /S:"C:\Users\Ann\Documents\{folder}"'
    assert gate("terminal", {"command": command}) == {
        "action": "block",
        "message": messages.WITNESS_AUTOSTART_BLOCKED,
    }


@pytest.mark.parametrize("folder", ["Profile", "Startup", "Cron"])
def test_an_ordinary_folder_with_a_generic_name_can_still_be_compressed(gate, folder):
    command = rf'MSYS_NO_PATHCONV=1 compact.exe /C /S:"C:\Users\Ann\Documents\{folder}"'
    assert gate("terminal", {"command": command})["action"] == "approve"


def test_the_skill_says_a_write_shows_only_the_start_of_its_content(gate):
    """r3-relay-skill-6: a write card shows the length, a digest and a preview, not every argument."""
    text = _normalized()
    assert "shows every argument in full" not in text
    assert "sees all of its arguments first" not in text
    assert "the first characters of the content" in text
    assert "tell the helper what the rest of the file contains" in text
    content = "line one of the note\n" * 40
    card = gate("write_file", {"path": "/home/sam/notes.txt", "content": content})
    assert card["action"] == "approve"
    assert content not in card["message"] and f"length={len(content)}" in card["message"]
