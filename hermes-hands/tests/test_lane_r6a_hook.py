"""Round-6 rules. A command line carried inside one argument (git grep -O'cp a .bashrc', tar
--to-command='crontab x', script -qc '...') is judged like the command itself. A sed script that
writes a file or runs a command is refused, as are wrappers that run any program. Read-only
diagnostics that name a startup word as a keyword (netsh wlan export profile, journalctl -u cron)
still reach the helper."""

import pytest

from hands import messages, witness
from test_lane_r3a_witness import fresh_tool_session, hook  # noqa: F401  (fixtures)

PERSISTENCE = {"action": "block", "message": messages.WITNESS_AUTOSTART_BLOCKED}
COMMAND = {"action": "block", "message": messages.WITNESS_COMMAND_BLOCKED}


@pytest.mark.parametrize(
    "command",
    [
        "sed -n w.bashrc /tmp/e",
        "sed -n W.profile /tmp/e",
        "sed -n wStartup/e.cmd /tmp/e.cmd",
        "sed -n '1e cp /tmp/e .bashrc' /tmp/e",
        "sed -n 1ecrontab\\ /tmp/c /tmp/e",
        "sed s/x/crontab/e /tmp/e",
        "sed s/x/y/w.bashrc /tmp/e",
        "sed -n w.zshrc /tmp/e",
        "sed -n 'w out.txt' /tmp/e",
        "sed -e p -e 'w out.txt' /tmp/e",
        "sed -ne w.bashrc /tmp/e",
        "sed -new.bashrc /tmp/e",
        "sed --expression=w.bashrc /tmp/e",
        "sed --expr w.bashrc /tmp/e",
        "sed -f script.sed /tmp/e",
        "sed --file=script.sed /tmp/e",
        "sed 1,3e /tmp/e",
        "sed '/x/e' /tmp/e",
        "sed 's|a|b|e' /tmp/e",
        "sed 's/a\\/b/c/we.txt' /tmp/e",
        "sed -n 'p;w out' /tmp/e",
        "sed.exe -n w.bashrc /tmp/e",
        "sed '1r /etc/passwd' /tmp/e",
    ],
)
def test_a_sed_script_that_writes_or_runs_is_blocked(hook, command):
    assert hook("terminal", {"command": command}) == COMMAND


@pytest.mark.parametrize(
    "command",
    [
        "sed -n '1,5p' /tmp/e",
        "sed s/a/b/g /tmp/e",
        "sed -n 2p notes.txt",
        "sed 's/a b/c d/gI' notes.txt",
        "sed -n '/error/p' /var/log/syslog",
        "sed -n '/start/,/end/p' notes.txt",
        "sed y/abc/xyz/ notes.txt",
        "sed 5q notes.txt",
        "sed -n = notes.txt",
        "sed -i s/a/b/ notes.txt",
        "sed -n 's/\\/x/y/p' notes.txt",
    ],
)
def test_a_print_or_substitute_sed_script_still_reaches_the_helper(hook, command):
    assert hook("terminal", {"command": command})["action"] == "approve"


@pytest.mark.parametrize(
    "command",
    [
        "git grep -O'cp /tmp/e .bashrc' foo",
        "git grep -O'systemctl --user enable e' foo",
        "git grep -O'crontab /tmp/c' foo",
        "tar -cf /dev/null --checkpoint=1 --checkpoint-action=exec='cp /tmp/e .bashrc' src",
        "tar -xf a.tar --to-command='cp /tmp/e .bashrc'",
        "tar -xf a.tar --to-command='crontab /tmp/c'",
        "zip x.zip src -T -TT 'cp /tmp/e .bashrc'",
        "vim -es -c 'w .bashrc' -c q /tmp/e",
        "vim -es '+w .bashrc' /tmp/e",
        "vim -es -c 'w Startup/e.cmd' /tmp/e",
        "git difftool -y -x 'cp /tmp/e .bashrc' HEAD",
        "make CMD='reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v e /d e.cmd /f'",
        "make CMD='reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v e /d e.cmd /f'",
        "make CMD='crontab /tmp/c'",
        "find /tmp -ok cp /tmp/e .bashrc +",
        "zip x.zip src -TT 'crontab /tmp/c'",
        "make CMD='CMD2=\"crontab /tmp/c\"'",
    ],
)
def test_persistence_inside_one_argument_is_blocked(hook, command):
    assert hook("terminal", {"command": command})["action"] == "block"


@pytest.mark.parametrize(
    "command",
    [
        "git grep -O'cp /tmp/e .bashrc' foo",
        "git grep -Ocrontab foo",
        "git grep -Osh foo",
        "git grep --open-files-in-pager=sh foo",
        "git grep --open foo",
        "git grep -iO foo",
        "git difftool -x sh HEAD",
        "git difftool --extcmd=sh HEAD",
        "script -qc 'cp /tmp/e .bashrc' /dev/null",
        "flock /tmp/l -c 'cp /tmp/e .bashrc'",
        "flock /tmp/l -c 'bash /tmp/x.sh'",
        "watch -n 600 'cp /tmp/e .bashrc'",
        "tmux new -d 'cp /tmp/e .bashrc'",
        "MSYS_NO_PATHCONV=1 forfiles /p . /m src /c 'cmd /c copy @path Startup'",
        "make CMD='sh /tmp/x.sh'",
        "make CMD='python3 /tmp/x.py'",
        "make CMD='/tmp/x.sh now'",
        "make CMD='start x.cmd'",
        "make CMD='sed -n w.bashrc x'",
        "make CMD='git grep -Osh x'",
        'make A=\'B="C=\\"D=e f\\""\'',
        "ionice -c3 sh /tmp/evil.sh",
        "taskset -c 0 sh /tmp/evil.sh",
        "chrt -o 0 sh /tmp/evil.sh",
        "strace -o /dev/null sh /tmp/evil.sh",
        "ltrace sh /tmp/evil.sh",
        "unbuffer sh /tmp/evil.sh",
        "caffeinate sh /tmp/evil.sh",
        "rg --pre sh x /tmp/evil.sh",
        "rg --pre=sh x /tmp/evil.sh",
        "find /tmp -exec sh /tmp/x.sh +",
        "find /tmp -execdir bash /tmp/x.sh +",
        "tar -xf a.tar --to-command=sh",
        "tar -xf a.tar --use-compress-program=/tmp/x.sh",
        "tar -cf /dev/null --checkpoint-action=exec=sh src",
        "zip x.zip src -TT sh",
        "vim -c w.bashrc -c q /tmp/e",
        "vim +w.bashrc /tmp/e",
        "vim -S /tmp/x.vim notes.txt",
        "vim -u /tmp/x.vim notes.txt",
        "nvim --cmd w.bashrc notes.txt",
        "ex -s -c wq notes.txt",
        "view +w.profile notes.txt",
        "rg --pre-glob x --pre sh x",
    ],
)
def test_a_program_run_by_another_program_is_refused(hook, command):
    assert hook("terminal", {"command": command}) == COMMAND


@pytest.mark.parametrize(
    "command",
    [
        'git commit -m "it\'s done"',
        "dir 'C:\\Program Files\\'",
        "git grep 'error budget' -- src",
        "grep 'cron job' /var/log/syslog",
        "grep -r 'startup error' /var/log",
        "MSYS_NO_PATHCONV=1 findstr /C:'Startup Type' notes.txt",
        "git log --grep='fix the build'",
        "ls '/c/Users/x/My Documents'",
        "cd '/c/Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs'",
        "MSYS_NO_PATHCONV=1 reg.exe query 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate",
        "MSYS_NO_PATHCONV=1 reg.exe add 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate /t REG_SZ /d 0 /f",
        "git commit -m 'Fix the printer queue'",
        "tar -xf a.tar -C 'My Folder'",
        "git grep -n foo",
        "git difftool --tool=meld HEAD",
        "rg -n foo src",
        "find /tmp -name x -type f",
        "zip -r x.zip src",
        "tar -czf backup.tar.gz notes",
        "netsh wlan export profile folder=C:/temp",
        "netsh wlan export profile 'folder=C:/My Backups'",
        "journalctl --user -u cron",
        "journalctl -u cron --since today",
        "journalctl -u anacron -n 50",
        "where python",
        "MSYS_NO_PATHCONV=1 taskkill.exe /IM node.exe",
        "tar -cf x.tar --checkpoint=100 src",
        "tar --to-stdout -xf a.tar notes",
        "ls '/c/Users/x/Start Menu'",
        "grep 'command not found' /var/log/syslog",
        "grep -r 'exec format error' /var/log",
        "MSYS_NO_PATHCONV=1 findstr /C:'time out' notes.txt",
        "ls '/c/Users/x/Source Code'",
        "ls '/Users/x/Desktop/Screen Shot 1.png'",
        "ls '/c/Users/x/Node Projects'",
        "MSYS_NO_PATHCONV=1 reg.exe query 'HKCU\\Software\\Microsoft\\Command Processor' /v AutoRun",
        "rg --pretty foo src",
        "vim notes.txt",
        "vim -R notes.txt",
        "make CMD='ls /c/Users/x/Start Menu'",
    ],
)
def test_ordinary_commands_with_spaces_or_keywords_still_reach_the_helper(hook, command):
    assert hook("terminal", {"command": command})["action"] == "approve"


@pytest.mark.parametrize(
    "command",
    [
        "netsh wlan export profile folder=Startup",
        "netsh wlan export profile folder=C:/Users/x/Start\\ Menu/Programs/Startup",
        "netsh wlan export profile folder=cron",
        "MSYS_NO_PATHCONV=1 netsh advfirewall export profile",
        "netsh wlan show profile folder=x export profile",
        "journalctl --cursor-file=.bashrc -u cron",
        "journalctl --cursor-file .bashrc -u cron",
        "journalctl -u cron --cursor-file Startup",
        "journalctl -u cron --cursor-file=Startup",
    ],
)
def test_a_read_only_diagnostic_still_refuses_a_startup_destination(hook, command):
    assert hook("terminal", {"command": command}) == PERSISTENCE


def test_command_lines_nested_deeper_than_two_levels_are_refused(hook):
    command = 'make A=\'B="C=\\"D=e f\\""\''
    assert hook("terminal", {"command": command}) == COMMAND
    assert witness._persistent_command(command)


def test_an_overlong_command_is_never_split_again():
    words = ["ls"] + [f"a b{index}" for index in range(100)]
    assert list(witness._inner_lines("ls", words)) == []
    assert list(witness._inner_lines("ls", words[:3])) == []
    assert list(witness._inner_lines("make", ["make", "CMD=ls notes"]))
