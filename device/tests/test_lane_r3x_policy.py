import pytest

from hermeshands_device import policy


@pytest.mark.parametrize("script", (
    "kill -9 `pgrep -f hermes`",
    "kill `pgrep python`",
    "kill $(pidof python3)",
    "kill `pidof python3`",
    "timeout 5 pkill python",
    "env pkill -f hermes",
    "env LANG=C pkill python",
    "nice pkill python",
    "nice -n 5 pkill python",
    "command pkill -f hermeshands_device",
    "exec pkill -f hermeshands_device",
))
def test_common_wrappers_and_substitutions_cannot_kill_agent(script):
    assert policy.refusal(script, policy.DEFAULTS)


@pytest.mark.parametrize("script", (
    "rg -n 'taskkill /IM python.exe' README.md",
    "printf '%s' 'Stop-Process -Name python'",
    "rg 'Get-Process python | Stop-Process' README.md",
    "printf '%s' 'kill $(pgrep python)'",
))
def test_process_kill_words_in_quoted_text_are_allowed(script):
    assert policy.refusal(script, policy.DEFAULTS) is None


@pytest.mark.parametrize("script", (
    'powershell -c "Stop-Process -Name python -Force"',
    'pwsh -Command "Get-Process python | Stop-Process"',
    'powershell.exe -NoProfile -Command "taskkill /IM python.exe /F"',
    "env taskkill /IM python.exe /F",
    "command Stop-Process -Name python",
))
def test_windows_kill_commands_in_executable_positions_are_blocked(script):
    assert policy.refusal(script, policy.DEFAULTS)


def test_disable_scheduled_task_is_blocked():
    assert policy.refusal(
        'powershell -c "Disable-ScheduledTask -TaskName HermesHands"',
        policy.DEFAULTS,
    )
