"""Command carriers are refused before real core dispatch reaches the Bash device."""

import shlex

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


@pytest.mark.parametrize("name", [
    "GIT_SSH_COMMAND", "GIT_SSH", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER",
    "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "GIT_PROXY_COMMAND", "GIT_EXEC_PATH",
    "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "SSH_ASKPASS", "PAGER", "EDITOR",
    "VISUAL", "LD_PRELOAD", "LD_AUDIT", "RSYNC_RSH",
])
@pytest.mark.parametrize("prefix", ["", "env "])
def test_environment_command_carrier_never_reaches_device(dispatch, name, prefix):
    d = dispatch
    result = d.invoke("terminal", {"command": f"{prefix}{name}=true git status", "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("command", [
    "git -c core.editor=true commit", "git -ccore.editor=true commit",
    "git --namespace scope -c core.editor=true commit",
    "git clone -c core.sshCommand=true source dest",
    "git clone --config=core.sshCommand=true source dest",
    "git -c core.sshCommand=true fetch", "git -c core.pager=true log",
    "git -c core.askPass=true fetch", "git -c core.gitProxy=true fetch",
    "git -c sequence.editor=true rebase", "git -c diff.external=true diff",
    "git -c alias.check='!true' check", "git --exec-path=/tmp status",
    "git --exec-path /tmp status", "git clone --upload-pack=true source dest",
    "git fetch --upload-pack true origin", "git push --receive-pack=true origin",
    "git clone -u true source dest", "git clone -utrue source dest",
    "git fetch -f --upload-pack=true origin", "git fetch -m --upload-pack=true origin",
    "git pull --upload-pack=true origin", "git pull --upload-pack true origin",
    "git ls-remote --upload-pack=true origin", "git ls-remote --upload-pack true origin",
    "git push --exec=true origin", "git push --exec true origin",
    "git archive --remote origin --exec=true HEAD", "git archive --remote origin --exec true HEAD",
    "git --exec-path status",
    "git --attr-source HEAD fetch --upload-pack=true origin",
    "git --attr-source=HEAD clone -u true source dest",
    "git push --receive-pack true origin", "git --config-env=core.editor=EDITOR commit",
    "git --config-env=alias.check=EDITOR check",
    "rsync -e true source dest", "rsync -etrue source dest", "rsync -ave true source dest",
    "rsync --rsh=true source dest", "rsync --rsh true source dest",
    "rsync --rsync-path=true source dest", "scp -S true source dest",
    "scp -Strue source dest", "scp -D true source dest",
    "scp -o ProxyCommand=true source dest", "scp -oProxyCommand=true source dest",
    "git grep -e pattern --open-files-in-pager=true", "git grep -e pattern -Otrue",
    "git grep -F -Otrue pattern", "git grep -F --open-files-in-pager=true pattern",
    "git -C . grep -F -Otrue pattern",
    "rsync --exclude '-temp' -e true src dest", "rsync --exclude '-temp' --rsh=true src dest",
    "docker run image", "docker container run image", "docker --context default exec container true",
])
def test_program_option_never_reaches_device(dispatch, command):
    d = dispatch
    if command.startswith("git "):
        assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("command", [
    "git commit -m 'start the server'", "git commit -m 'bash repair.sh'",
    "git commit -m 'core.editor=true'", "git commit -m '--upload-pack=true'",
    "git grep -c 'core.editor=true'", "git -c color.ui=false grep -c 'core.editor=true'",
    "git --attr-source HEAD grep -c 'core.editor=true'",
    "git commit -c 'core.editor=true'", "git commit -t '--upload-pack=true'",
    "git fetch -f origin", "git fetch -m origin", "git push -u origin",
    "git grep -f '--upload-pack=true'", "git grep -m 1 -e '--upload-pack=true'",
    "git -c color.ui=false status", "echo 'GIT_EDITOR=true'", "echo 'start the server'",
    "LANG=C git status",
    "git grep -e '--upload-pack=true'", "rsync --exclude '-temp' src dest",
    "docker image inspect run", "git grep -- --upload-pack=true",
    "rsync -- --rsh=true dest", "docker image inspect exec",
    "git commit -m grep", "git commit -m difftool",
    "git difftool", "git mergetool",
    "git commit -c HEAD", "git commit -m '--exec x'", "git log -S --exec",
    "git status -- --upload-pack=true", "git status -- --exec=true",
    "git config --get core.editor", "git config --get-all credential.helper",
    "git config --list", "git config -l", "git config --get alias.f",
    "git config --global --get core.sshCommand", "git config --file isolated-config --get core.editor",
    "git -c ssh.variant=ssh status", "git config ssh.variant ssh",
    "git send-email --dry-run patch",
    "git log --grep '--upload-pack=true'",
])
def test_ordinary_data_still_reaches_exact_approved_device_job(dispatch, command):
    d = dispatch
    assert d.base in d.call("terminal", {"command": "pwd", "timeout": 5})
    d.jobs.clear()
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED not in result, result
    assert len(d.cards) == len(d.answers) == len(d.jobs) == 1
    assert "command=" + command + "; timeout=5" in d.cards[0]
    assert command.replace("'", "'\\''") in d.jobs[0]["script"], d.jobs


@pytest.mark.parametrize("command", [
    "git ls-remote --exec=true origin", "git ls-remote --exec true origin",
    "git ls-remote --ex=true origin", "git ls-remote --ex true origin",
    "git fetch-pack --upload-pack=true origin", "git fetch-pack --upload-pack true origin",
    "git fetch-pack --up=true origin", "git send-pack --receive-pack=true origin",
    "git send-pack --receive-pack true origin", "git send-pack --rec=true origin",
    "git status --upload-pack=true", "git status --receive-pack=true", "git status --exec=true",
    "git status --exec-path=/tmp", "git status --upload-archive=true",
    "git status --ssh-command=true", "git status --sendmail-cmd=true",
    "git status --up=true", "git status --rec=true", "git status --ex=true",
    "git upload-pack --upload-pack=true origin", "git receive-pack --receive-pack=true origin",
    "git rebase -x true main", "git rebase -xtrue main",
    "git rebase --exec 'make test' main", "git rebase --exec='make test' main",
    "git bisect run true", "git submodule foreach true",
    "git submodule --quiet foreach true", "git filter-branch",
    "git filter-branch --tree-filter true main", "git filter-branch --index-filter true main",
    "git filter-branch --msg-filter true main", "git filter-branch --env-filter true main",
    "git send-email --sendmail-cmd true patch", "git send-email --sendmail-cmd=true patch",
    "git send-email --smtp-server /usr/sbin/sendmail patch",
    "git send-email --smtp-server=/usr/sbin/sendmail patch",
    "git send-email --smtp-server ./sendmail patch",
    "git send-email --smtp-server=C:/bin/sendmail.exe patch",
    "git difftool -x true", "git difftool -xtrue", "git difftool --extcmd=true",
    "git difftool --ext true", "git difftool --ext=sh",
    "git daemon", "git instaweb",
    "git credential fill", "git credential-cache get", "git credential-store get",
])
def test_git_command_carriers_refused_before_any_job(dispatch, monkeypatch, command):
    import test_lane_p8_findings

    monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: ("unexpected Git job", 1))
    d = dispatch
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("key", [
    "core.editor", "core.sshCommand", "core.pager", "core.hooksPath", "core.fsmonitor",
    "core.askPass", "core.gitProxy", "credential.helper", "diff.external", "sequence.editor",
    "gpg.program", "gpg.ssh.program", "gpg.x509.program", "merge.custom.driver",
    "diff.custom.textconv", "filter.custom.clean", "filter.custom.smudge", "filter.custom.process",
    "alias.f", "difftool.custom.cmd", "mergetool.custom.cmd",
])
@pytest.mark.parametrize("template", [
    "git -c {key}=true status", "git -c{key}=true status",
    "git config {key} true", "git config --global {key} true",
    "git config --system {key} true", "git config --local {key} true",
    "git config --file isolated-config {key} true", "git config --add {key} true",
    "git config --replace-all {key} true", "git config --unset {key}",
])
def test_git_program_config_cannot_be_written(dispatch, monkeypatch, key, template):
    import test_lane_p8_findings

    monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: ("unexpected Git job", 1))
    d = dispatch
    command = template.format(key=key)
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("command", [
    "git f --upload-pack=true origin", "git f --upload-pack true origin",
    "git f --ex=true origin", "git f", "git not-a-built-in status",
])
def test_unknown_git_subcommand_may_be_alias_and_never_reaches_device(dispatch, monkeypatch, command):
    import test_lane_p8_findings

    monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: ("unexpected Git job", 1))
    d = dispatch
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED in result, result
    assert "unknown git subcommand, may be an alias" in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("command", [
    "git -c alias.f=fetch f --upload-pack=true origin",
    "git -c alias.f='fetch --upload-pack=true' f",
    "git config alias.f 'fetch --upload-pack=true'",
    "git config alias.f '!true'",
])
def test_git_alias_definitions_never_reach_device(dispatch, monkeypatch, command):
    import test_lane_p8_findings

    monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: ("unexpected Git job", 1))
    d = dispatch
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("command", [
    "git send-pack --force-with-lease --receive-pack=true origin",
    "git clone --conf=core.editor=true source dest",
    "git clone --conf core.editor=true source dest",
    "git clone -qc core.editor=true source dest",
])
def test_git_option_value_consumption_does_not_hide_program_selectors(dispatch, monkeypatch, command):
    import test_lane_p8_findings

    monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: ("unexpected Git job", 1))
    d = dispatch
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    assert messages.WITNESS_COMMAND_BLOCKED in result, result
    assert d.cards == [] and d.answers == [] and d.jobs == []


@pytest.mark.parametrize("command,blocked", [
    ("git config --rename-section harmless core", True),
    ("git config --rename-section harmless alias", True),
    ("git config rename-section harmless core", True),
    ("git config rename-section harmless alias", True),
    ("git config --rename-section harmless ordinary", False),
    ("git config rename-section harmless ordinary", False),
])
def test_git_config_section_rename_cannot_create_program_settings(dispatch, monkeypatch, command, blocked):
    import test_lane_p8_findings

    d = dispatch
    if not blocked:
        assert d.base in d.call("terminal", {"command": "pwd", "timeout": 5})
        d.jobs.clear()
    monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: ("Git config job", 1))
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    if blocked:
        assert messages.WITNESS_COMMAND_BLOCKED in result, result
        assert d.cards == [] and d.answers == [] and d.jobs == []
    else:
        assert messages.WITNESS_COMMAND_BLOCKED not in result, result
        assert len(d.cards) == len(d.answers) == len(d.jobs) == 1
        assert "command=" + command + "; timeout=5" in d.cards[0]
        assert command in d.jobs[0]["script"], d.jobs


@pytest.mark.parametrize("command,blocked", [
    ("git log --pretty --exec=true", True),
    ("git show --pretty --exec=true", True),
    ("git show --format --exec=true", True),
    ("git log --format '--upload-pack=true'", True),
    ("git log --format='--upload-pack=true'", False),
    ("git show --format='--upload-pack=true'", False),
    ("git log --pretty='--upload-pack=true'", False),
    ("git show --pretty='--upload-pack=true'", False),
])
def test_git_attached_only_format_options_do_not_hide_program_selectors(dispatch, monkeypatch, command, blocked):
    import test_lane_p8_findings

    d = dispatch
    if blocked:
        monkeypatch.setattr(test_lane_p8_findings, "bash_job", lambda job: ("unexpected Git job", 1))
    else:
        assert d.base in d.call("terminal", {"command": "pwd", "timeout": 5})
        d.jobs.clear()
    result = d.invoke("terminal", {"command": command, "timeout": 5})
    if blocked:
        assert messages.WITNESS_COMMAND_BLOCKED in result, result
        assert d.cards == [] and d.answers == [] and d.jobs == []
    else:
        assert messages.WITNESS_COMMAND_BLOCKED not in result, result
        assert len(d.cards) == len(d.answers) == len(d.jobs) == 1
        assert "command=" + command + "; timeout=5" in d.cards[0]
        assert command.replace("'", "'\\''") in d.jobs[0]["script"], d.jobs


@pytest.mark.parametrize("command", [
    "git --shallow-file push origin",
    "git --shallow-file nofile push --receive-pack=true origin",
    "git grep --regexp --exec=true",
    "git mergetool -O --exec=true",
    "git fetch-pack --depth --exec=true",
    "git fetch-pack --shallow-since --exec=true",
    "git fetch-pack --shallow-exclude --exec=true",
    "git fetch-pack --filter --exec=true",
    "git difftool -yxtrue HEAD",
    "git difftool -M -xtrue HEAD",
    "git difftool -C -xtrue HEAD",
    "git difftool -B -xtrue HEAD",
    "git difftool -U -xtrue HEAD",
    "git difftool -I -xtrue HEAD",
    "git difftool --word-diff-regex -xtrue HEAD",
    "git -c alias.check='!true' check",
    "git config alias.f '!true'",
    "git --exec-path /tmp status",
    *[f"git send-email {option}{separator}true patch" for option in (
        "--to-cmd", "--to-cm", "--cc-cmd", "--cc-cm", "--header-cmd", "--header-c",
        "--smtp-server",
    ) for separator in ("=", " ")],
    "git send-email --dry-run --smtp-server smtp.example.com patch",
    "git init --t=tpl", "git init --t tpl",
    "git init-db --template=tpl", "git init-db --t tpl",
    *[f"git {command} {option}{separator}tpl" for command in ("clone", "init")
      for option in ("--template", "--templ") for separator in ("=", " ")],
])
def test_git_review_carriers_are_decided_by_git_logic(command):
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    assert witness._command_decision(command)["action"] == "block"


@pytest.mark.parametrize("key", [
    "tar.a.b.command", "imap.tunnel", "credential.https://a.b.example.com.helper",
    "remote.a.b.uploadpack", "remote.a.b.receivepack", "remote.a.b.vcs",
    "sendemail.sendmailcmd", "sendemail.tocmd", "sendemail.cccmd", "sendemail.smtpserver",
    "sendemail.headercmd", "sendemail.a.b.tocmd", "sendemail.a.b.smtpserver",
    "uploadpack.packObjectsHook", "core.alternateRefsCommand",
    "difftool.a.b.path", "difftool.a.b.cmd", "mergetool.a.b.path", "mergetool.a.b.cmd",
    "gpg.program", "gpg.a.b.program", "gpg.ssh.defaultKeyCommand",
    "man.a.b.cmd", "man.a.b.path", "man.viewer", "web.browser",
    "browser.a.b.cmd", "browser.a.b.path", "submodule.a.b.update",
    "init.templateDir", "include.path", "includeIf.gitdir:/a.b/.path",
    "protocol.allow", "protocol.a.b.allow",
    "gc.recentObjectsHook", "guitool.a.b.cmd", "interactive.diffFilter",
    "instaweb.browser", "instaweb.httpd", "help.browser",
    "trailer.a.b.cmd", "trailer.a.b.command", "hook.a.b.command",
])
@pytest.mark.parametrize("template", [
    "git -c {key}=true status", "git --config-env={key}=VALUE status",
    "git clone --config={key}=true source dest", "git config set {key} true",
])
def test_git_documented_program_configuration_is_refused(key, template):
    command = template.format(key=key)
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    assert witness._command_decision(command)["action"] == "block"
    upper = template.format(key=key.upper())
    assert witness._git_runs_program(*witness._git_parts(shlex.split(upper)[1:])) is True
    for mode in ("--get", "--list", "get"):
        read = f"git config {mode} {key}"
        assert witness._git_runs_program(*witness._git_parts(shlex.split(read)[1:])) is False


@pytest.mark.parametrize("arguments,global_arguments", [
    (["--shallow-file", "push"], ["--shallow-file", "push"]),
    (["-C", "."], ["-C", "."]), (["-C."], ["-C."]),
    (["-c", "color.ui=false"], ["-c", "color.ui=false"]),
    (["-ccolor.ui=false"], ["-ccolor.ui=false"]),
    *[([name, "--exec=true"], [name, "--exec=true"]) for name in (
        "--git-dir", "--work-tree", "--namespace", "--attr-source",
    )],
    *[([name + "=--exec=true"], [name + "=--exec=true"]) for name in (
        "--git-dir", "--work-tree", "--namespace", "--attr-source",
    )],
    (["--config-env", "color.ui=VALUE"], ["--config-env", "color.ui=VALUE"]),
    (["--config-env=color.ui=VALUE"], ["--config-env=color.ui=VALUE"]),
])
def test_git_global_option_values_do_not_become_subcommands_or_program_flags(arguments, global_arguments):
    parts = witness._git_parts(arguments + ["status"])
    assert parts == (global_arguments, "status", [])
    assert witness._git_runs_program(*parts) is False


@pytest.mark.parametrize("command", [
    "git difftool -Sfix HEAD", "git difftool -Gfoox HEAD", "git difftool -Sfoox HEAD",
    "git difftool -Ifoox HEAD", "git difftool -Ofoox HEAD", "git difftool -Ufoox HEAD",
    "git difftool -lfoox HEAD", "git difftool -Mfoox HEAD", "git difftool -Cfoox HEAD",
    "git difftool -Bfoox HEAD", "git difftool -Xfoox HEAD",
    "git difftool -ax HEAD", "git difftool -yax HEAD",
    "git difftool -ySfix HEAD", "git difftool -yGfoox HEAD",
    "git difftool --diff-filter x HEAD", "git difftool --word-diff-regex x HEAD",
    "git difftool -S --exec=true HEAD",
])
def test_git_diff_patterns_do_not_select_an_external_command(command):
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is False
    assert witness._command_decision(command)["action"] == "approve"


@pytest.mark.parametrize("section", [
    "tar.a.b", "remote.a.b", "sendemail.a.b", "man.a.b", "browser.a.b",
    "submodule.a.b", "init", "include", "includeIf.gitdir:/a.b/", "protocol.a.b",
    "gc", "interactive", "instaweb", "hook.a.b", "trailer.a.b", "guitool.a.b",
])
def test_git_section_rename_cannot_install_new_program_keys(section):
    command = f"git config --rename-section harmless {section}"
    assert witness._git_runs_program(*witness._git_parts(shlex.split(command)[1:])) is True
    assert witness._command_decision(command)["action"] == "block"
