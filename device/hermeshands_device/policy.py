from __future__ import annotations

import json
import os
import re
import sys

from . import config
from .protocol import canonical_json, policy_hash

# A command word after common shell wrappers, assignments and an optional path.
_COMMAND = (
    r"(?:^|[\r\n;&|(`]|\$\()\s*"
    r"(?:(?:[A-Za-z_]\w*=\S*|sudo|env|command|exec|nice(?:\s+-n\s+-?\d+)?|timeout\s+\d+(?:\.\d+)?[smhd]?)\s+)*"
    r"(?:(?:powershell|pwsh)(?:\.exe)?\s+(?:-NoProfile\s+)?-(?:c|Command)\s+['\"]?\s*)?"
    r"(?:[^\s;&|()'\"`]*[\\/])?['\"]?"
)
# The agent's own process names as one whole argument, the way pkill, killall and pgrep match them.
_AGENT = r"(?:hermes[-_.]?hands?|hermes|hands|hermeshands_device(?:\.cli)?|python(?:w|[0-9]+(?:\.[0-9]+)*)?)(?:\.exe)?"
_AGENT_ARG = rf"""(?:"{_AGENT}"|'{_AGENT}'|{_AGENT})(?=[\s'"`]|$|[;&|)])"""
# The same names for Windows tools, which also take * wildcards.
_AGENT_GLOB = r"(?:hermes-?hands|hermes\*|python(?:w|[0-9]+(?:\.[0-9]+)*)?|p(?:y(?:t(?:h(?:o(?:n)?)?)?)?)?\*)(?:\.exe)?"
_AGENT_GLOB_ARG = rf"""(?:"{_AGENT_GLOB}"|'{_AGENT_GLOB}'|{_AGENT_GLOB})(?=[\s'"]|$|[;&|)])"""

DEFAULTS = [
    r"(?:^|[\s;&|(`'\"])(?:(?:\"[^\"]*[\\/]|'[^']*[\\/]|[^\s;&|()'\"`]+[\\/])*)hermes-?hands(?:\.exe)?[\"']?\s+(?:pair|unpair|serve|install-service|policy)\b|"
    r"(?:^|[\s;&|(`'\"])(?:(?:\"[^\"]*[\\/]|'[^']*[\\/]|[^\s;&|()'\"`]+[\\/])*)(?:python(?:w|[0-9]+(?:\.[0-9]+)*)?|py)(?:\.exe)?[\"']?(?:\s+-(?!m(?:\s|hermeshands_device))[^\s]+(?:\s+(?!-)[^\s]+)?)*\s+-m\s*hermeshands_device(?:\.cli)?\s+(?:pair|unpair|serve|install-service|policy)\b|"
    r"\b(?:pipx|pip|runpip|uv\s+(?:tool|pip))\s+uninstall\s+hermes-?hands\b|\bpython\s+-m\s+pip\s+uninstall\s+hermes-?hands\b|^\s*hermeshands\s*$",
    r"\.hermes-hands(?:[/\\]|\b)",
    r"\b(?:taskkill|Stop-Process|kill)\b.*(?:\$\{?PPID\}?|<agent-pid>)",
    # Other Windows schtasks task names and WMI process termination remain outside these patterns.
    r"\b(?:schtasks\s+/{1,2}(?:End|Delete|Change)|Stop-ScheduledTask|Disable-ScheduledTask|Unregister-ScheduledTask)\b.*HermesHands|\btaskkill\b.*(?:/|//|-)(?:F|IM)\b.*hermes-?hands(?:\.exe)?\b|\bkillall\s+hermes-?hands(?:\.exe)?\b",
    # Killing the agent by process name. Best effort: a name spelled to avoid these still gets through.
    rf"{_COMMAND}(?:pkill|killall)['\"]?(?:\s+[^\s;&|]+)*?\s+{_AGENT_ARG}|"
    rf"{_COMMAND}kill\b[^\r\n;&|]*?(?:\$\(|`)\s*(?:pgrep|pidof)(?:\s+[^\s;&|)`]+)*?\s+{_AGENT_ARG}|"
    rf"{_COMMAND}pgrep(?:\s+[^\s;&|]+)*?\s+{_AGENT_ARG}[^\r\n;&]*\|\s*xargs\b[^\r\n;&|]*\bkill\b|"
    rf"{_COMMAND}taskkill\b[^\r\n;&|]*(?:/{{1,2}}|-)IM\s+{_AGENT_GLOB_ARG}|"
    rf"{_COMMAND}taskkill\b[^\r\n;&|]*IMAGENAME\s+eq\s+{_AGENT_GLOB}(?=[\s'\"]|$)|"
    rf"{_COMMAND}Stop-Process\b[^\r\n;&|]*-(?:Process)?Name\s+{_AGENT_GLOB_ARG}|"
    rf"{_COMMAND}Get-Process\b(?:\s+-(?:Process)?Name)?\s+{_AGENT_GLOB_ARG}[^\r\n;&]*\|\s*Stop-Process\b",
    r"\bsudo\b",
    r"(?:rm\s+-rf\s+(?:/(?:\s|$)|['\"]?(?:~/?|\$HOME/?)['\"]?(?:\s|$))|\bRemove-Item\b.*(?:[A-Za-z]:\\|[/\\])(?:\s|$).*?-Recurse)",
    r"\bmkfs(?:\.[\w-]+)?\b|\bdd\b.*\bof=/dev/",
    r"\bdiskpart\b|(?:^|[\r\n;&|()])\s*(?:MSYS_NO_PATHCONV=1\s+)?(?:cmd(?:\.exe)?\s+/c\s+)?(?:[A-Za-z]:\\(?:[^\\\s;&|()]+\\)*)?format(?:\.com)?\s+[A-Za-z]:",
    r"\b(?:shutdown|reboot|Stop-Computer)\b",
    r"(?:curl|wget|Invoke-WebRequest).*\|\s*(?:sh|bash|pwsh|powershell)",
    r"(?:taskkill\s+/PID\s+<agent-pid>\b|Stop-Process\b.*-Id\s+<agent-pid>\b|\bkill\s+-?9?\s+<agent-pid>\b)",
]


def patterns() -> list[str]:
    return snapshot()[1]


def reset() -> str:
    if "HERMES_HANDS_JOB" in os.environ:
        raise PermissionError("policy reset is unavailable from a Hermes Hands device job")
    config.ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = canonical_json({"deny": DEFAULTS})
    config.POLICY_PATH.write_bytes(raw)
    if sys.platform != "win32":
        config.POLICY_PATH.chmod(0o600)
    return policy_hash(raw)


def digest() -> str:
    return snapshot()[0]


def snapshot() -> tuple[str, list[str]]:
    if config.POLICY_PATH.exists():
        raw = config.POLICY_PATH.read_bytes()
        deny = json.loads(raw.decode("utf-8-sig"))["deny"]
    else:
        raw = canonical_json({"deny": DEFAULTS})
        deny = DEFAULTS.copy()
    return policy_hash(raw), deny


def refusal(script: str, deny: list[str] | None = None) -> str | None:
    normalized = re.sub(r"(?<=\w)['\"\\]+(?=\w)", "", script)
    normalized_self = re.sub(r"['\"\\]", "", script)
    for index, pattern in enumerate(patterns() if deny is None else deny):
        active_pattern = pattern.replace("<agent-pid>", rf"(?<!\d){os.getpid()}(?!\d)")
        if re.search(active_pattern, script, re.IGNORECASE) or re.search(active_pattern, normalized, re.IGNORECASE) or index < 4 and re.search(active_pattern, normalized_self, re.IGNORECASE):
            return pattern
    return None


def check(script: str) -> int:
    pattern = refusal(script)
    if pattern:
        print(f"Policy refused command matching: {pattern}")
        return 126
    return 0


def show() -> None:
    for item in patterns():
        print(item)
