"""The witness persistence claims in README.md and SKILL.md match the hook's real behaviour."""

import re
from pathlib import Path

import pytest

from hands import witness

REPO = Path(__file__).resolve().parents[2]


def _text(path: Path) -> str:
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8-sig"))


README = _text(REPO / "README.md")
SKILL = _text(REPO / "hermes-hands" / "skills" / "hands" / "SKILL.md")


@pytest.mark.parametrize(
    ("command", "refused"),
    [
        ("grep -n startup notes.txt", False),
        ("rg startup", False),
        ("git grep startup", False),
        ("findstr startup notes.txt", False),
        ("systemctl cat backup.service", False),
        ("cp -r units /home/ann/.config/systemd", False),
        ("cat /home/ann/.config/autostart/app.desktop", True),
        ("cat profile", True),
        ("cat crontab", True),
        ("cat bashrc", True),
        ("cd /home/ann/.config/systemd", True),
        ("cd /home/ann/.config/fish", True),
        ("cd /home/ann/.config/plasma-workspace", True),
        ("explorer.exe shell:startup", True),
        ("cp -tStartup run.cmd", True),
        ("cp unit.service /home/ann/.config/systemd/user/unit.service", True),
        ("cp unit.service user/unit.service", True),
    ],
)
def test_the_documented_persistence_behaviour_is_the_hook_behaviour(command, refused):
    assert witness._persistent_command(command) is refused


def test_the_readme_describes_what_the_persistence_block_covers():
    assert "even when it only reads it" not in README
    for words in (
        "systemd user folders", "`user/<unit>`", "recursive copy", "`grep`, `rg`, `git grep` and `findstr`",
        "`profile`, `crontab` and `bashrc`", "`systemd`, `fish` or `plasma-workspace`",
        "`explorer.exe shell:startup`", "`cp -tStartup`",
    ):
        assert words in README, words


def test_the_readme_limits_name_the_persistence_routes_that_only_reach_approval():
    limits = README.split("## Known limits", 1)[1].split("\n## ", 1)[0]
    for words in ("`AutoRun`", "`at`", "`launchctl load`", "`sc create`", "symlink", "recursive extract"):
        assert words in limits, words
    assert "`systemd-run`" not in limits
    assert witness._command_decision("systemd-run service") == {"action": "block", "message": witness.messages.WITNESS_COMMAND_BLOCKED}


def test_the_skill_says_a_bare_startup_name_is_a_search_term_and_names_the_refused_folders():
    assert "`grep`, `rg` and `git grep`" in SKILL
    assert "`systemctl cat <unit>`" in SKILL
    disk = SKILL.split("### Disk full (Windows only)", 1)[1].split("###", 1)[0]
    for folder in ("`systemd`", "`fish`", "`plasma-workspace`"):
        assert folder in disk, folder


@pytest.mark.parametrize(
    "folder", ["systemd/user", "fish/conf.d", "fish/functions", "plasma-workspace/env", "plasma-workspace/shutdown"]
)
def test_the_login_folders_the_skill_sends_to_the_manual_steps_are_refused(folder):
    command = rf'MSYS_NO_PATHCONV=1 compact.exe /C /S:"C:\Users\Ann\Documents\{folder}"'

    assert witness._persistent_command(command) is True
