"""Round-4 persistence path rules. A generic folder or file name (startup, cron, profile, crontab)
counts only where the OS reads it: under its OS parent, or as the first part of a relative path
whose real parent is unknown (the terminal folder or a drive's own current folder can be anything).
Win32 trims trailing dots and spaces from every part, so the bare-word check does the same."""

import pytest

from hands import messages
from test_lane_r3a_witness import fresh_tool_session, hook  # noqa: F401  (fixtures)

PERSISTENCE = {"action": "block", "message": messages.WITNESS_AUTOSTART_BLOCKED}
START_MENU = "/c/Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs"


@pytest.mark.parametrize(
    "command",
    [
        "xcopy /c/Users/x/evil.cmd Startup.",
        "MSYS_NO_PATHCONV=1 xcopy C:/Users/x/evil.cmd Startup. /Y",
        "xcopy /c/Users/x/evil.cmd 'Startup '",
        "xcopy /c/Users/x/evil.cmd 'Startup. .'",
        "robocopy . Startup. evil.cmd",
        "cp evil.cmd CRON.",
        "cp evil.cmd Startup/",
        "cp evil.cmd ./Startup",
        "cp evil.cmd ../Startup",
        "cp evil.cmd Programs/Startup",
        "cp evil.cmd ../../Programs/Startup/evil.cmd",
        "cp evil.cmd C:Startup",
        "cp evil.cmd 'C:Programs\\Startup\\evil.cmd'",
        f"cp evil.cmd '{START_MENU}/Startup'",
        f"cp evil.cmd '{START_MENU}./Startup. '",
        "cp evil.cmd 'C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/evil.cmd'",
        "cp job /var/spool/cron/crontabs/x",
        "cp job /etc/cron/x",
        "cp job /usr/lib/cron/tabs/x",
        "cp job /etc/crontab",
        "cp evil /etc/profile",
        "cp evil ./profile",
        "cp evil ./crontab",
        "cp job cron/x",
        "cp evil /home/x/work/autostart/x.desktop",
    ],
)
def test_startup_persistence_through_a_trimmed_or_relative_name_is_blocked(hook, command):
    assert hook("terminal", {"command": command}) == PERSISTENCE


@pytest.mark.parametrize(
    "path",
    [
        f"{START_MENU}/Startup/evil.cmd",
        f"{START_MENU}/Startup./evil.cmd",
        "Startup/evil.cmd",
        "../Startup/evil.cmd",
        "C:Startup/evil.cmd",
        "/etc/profile",
        "/etc/crontab",
        "/var/spool/cron/x",
        "profile",
    ],
)
def test_startup_persistence_writes_are_blocked(hook, path):
    assert hook("write_file", {"path": path, "content": "x"}) == PERSISTENCE


@pytest.mark.parametrize(
    "command",
    [
        "git log src/startup/main.py",
        "ls /c/Users/x/projects/cron",
        "cat /c/Users/x/profile",
        "cat /c/Users/x/projects/crontab",
        "ls /c/Users/x/Startup",
        "cp notes.txt /c/Users/x/work/startup/notes.txt",
        'MSYS_NO_PATHCONV=1 compact.exe /C /S:"C:\\Users\\Margaret\\Documents\\Profile"',
    ],
)
def test_ordinary_paths_that_only_share_a_name_still_reach_the_helper(hook, command):
    assert hook("terminal", {"command": command})["action"] == "approve"


@pytest.mark.parametrize(
    "path",
    [
        "/c/Users/x/work/startup/config.json",
        "/c/Users/x/projects/cron/notes.txt",
        "/c/Users/x/profile",
        "~/Documents/Profile/notes.txt",
        "/home/x/src/startup/main.py",
    ],
)
def test_ordinary_writes_that_only_share_a_name_still_reach_the_helper(hook, path):
    assert hook("write_file", {"path": path, "content": "x"})["action"] == "approve"


def test_a_workdir_one_level_above_startup_is_allowed_but_the_bare_folder_is_not(hook):
    assert hook("terminal", {"command": "ls", "workdir": START_MENU})["action"] == "approve"
    assert (
        hook("terminal", {"command": "cp evil.cmd Startup", "workdir": START_MENU}) == PERSISTENCE
    )
    assert hook("terminal", {"command": "ls", "workdir": "Startup"}) == PERSISTENCE
