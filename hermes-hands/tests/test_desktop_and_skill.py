"""The Desktop half (``desktop/plugin.js``) against core's admission lint, the Desktop loader's
import rules and the /hands output it reads, and the bundled ``hands`` skill through the real
``PluginContext.register_skill``."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from hands import commands, store
from hands_fakes import (  # noqa: F401
    PLUGIN_DIR,
    Device,
    RegisterCtx,
    hands_db,
    load_plugin_package,
)

PLUGIN_JS = PLUGIN_DIR / "desktop" / "plugin.js"
SKILL_MD = PLUGIN_DIR / "skills" / "hands" / "SKILL.md"
# apps/desktop/src/contrib/runtime-loader.ts: importSpecifierRe and sdkImportMap.
_SPECIFIER = re.compile(r"""(from\s*|import\s*\(\s*|import\s+)(['"])([^'"]+)\2""")
_LOADER_SPECIFIERS = {"@hermes/plugin-sdk", "react", "react/jsx-runtime", "react/jsx-dev-runtime"}


def test_desktop_surface_check_passes_with_no_review_cues():
    pytest.importorskip("hermes_cli.plugin_validate_desktop")
    from hermes_cli.plugin_validate import ValidationReport
    from hermes_cli.plugin_validate_desktop import check_desktop_surface

    report = ValidationReport()
    check_desktop_surface(report, PLUGIN_DIR)
    assert report.checks == [("desktop surface", True, "stays inside the plugin SDK surface")]
    assert report.warnings == []


def test_desktop_imports_only_what_the_loader_resolves():
    source = PLUGIN_JS.read_text(encoding="utf-8-sig")
    specifiers = {match.group(3) for match in _SPECIFIER.finditer(source)}
    assert specifiers and specifiers <= _LOADER_SPECIFIERS


def _sdk_exports(sdk_dir: Path, module: str) -> set[str]:
    """Runtime names a TypeScript module exports: ``export { a, b as c }`` blocks (``type`` entries
    skipped), ``export const|function|class``, ``export * as ns`` and ``export * from './x'``."""
    source = (sdk_dir / f"{module}.ts").read_text(encoding="utf-8-sig")
    names = set(re.findall(r"^export (?:const|function|class) (\w+)", source, re.M))
    names |= set(re.findall(r"^export \* as (\w+)", source, re.M))
    for block in re.findall(r"^export \{([^}]*)\}", source, re.M):
        for entry in (item.strip() for item in block.split(",")):
            if entry and not entry.startswith("type "):
                names.add(entry.split(" as ")[-1].strip())
    for local in re.findall(r"^export \* from '\./(\w[\w-]*)'", source, re.M):
        names |= _sdk_exports(sdk_dir, local)
    return names


def test_every_sdk_name_the_pane_imports_is_exported():
    """A name the SDK does not export fails the whole module at link time on the Desktop."""
    hermes_cli = pytest.importorskip("hermes_cli")
    sdk_dir = Path(hermes_cli.__file__).resolve().parents[1] / "apps" / "desktop" / "src" / "sdk"
    if not (sdk_dir / "index.ts").is_file():
        pytest.skip("the Hermes checkout has no apps/desktop source")
    source = PLUGIN_JS.read_text(encoding="utf-8-sig")
    [block] = re.findall(r"import \{([^}]*)\} from \"@hermes/plugin-sdk\"", source)
    imported = {name.strip() for name in block.split(",") if name.strip()}
    assert imported - _sdk_exports(sdk_dir, "index") == set()


def test_desktop_file_parses_as_an_es_module(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    module = tmp_path / "plugin.mjs"
    shutil.copyfile(PLUGIN_JS, module)
    checked = subprocess.run(
        [node, "--check", str(module)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert checked.returncode == 0, checked.stderr


class SkillCtx(RegisterCtx):
    def register_hook(self, hook_name, callback, *, hold_stream=False):
        self.calls.append(("hook", hook_name))

    def register_skill(self, name, path, description="", frontmatter=None):
        self.skill = (name, path, description)


def test_register_bundles_the_hands_skill(hands_db, monkeypatch):
    pytest.importorskip("agent.secret_scope")
    pytest.importorskip("hermes_cli.dashboard_auth.token_auth")
    import yaml
    from hermes_cli.dashboard_auth import registry, token_auth
    from hermes_cli.plugins import PluginContext, PluginManager
    from hermes_cli.plugins_manifest import PluginManifest

    monkeypatch.delenv("HANDS_RELAY_SEED", raising=False)
    ctx = SkillCtx()
    load_plugin_package().register(ctx)
    assert ("hook", "pre_tool_call") in ctx.calls
    provider = dict((kind, obj) for kind, obj in ctx.calls if kind == "auth")["auth"]
    try:
        name, path, description = ctx.skill
        manager = PluginManager()
        PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager).register_skill(
            name, path, description
        )
        assert manager.find_plugin_skill("hermes-hands:hands") == SKILL_MD
        frontmatter = yaml.safe_load(SKILL_MD.read_text(encoding="utf-8-sig").split("---")[1])
        assert frontmatter == {"name": name, "description": description}
    finally:
        registry.unregister_global_provider(provider.name, provider)
        token_auth.clear_token_routes()


def test_manifest_advertises_the_checkup_tool():
    import yaml

    manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8-sig"))

    assert manifest["version"] == "0.2.0"
    assert {"hands_screenshot", "hands_devices", "hands_checkup"} <= set(
        manifest["provides_tools"]
    )


def test_hands_skill_starts_checkup_requests_with_builtin_tool():
    source = " ".join(SKILL_MD.read_text(encoding="utf-8-sig").split()).casefold()

    assert "call `hands_checkup` as your first tool call" in source
    assert "ad hoc terminal commands on witness devices are blocked or require owner approval" in source
    assert "ask any clarifying questions after the checkup" in source


def test_f4_playbooks_keep_diagnostics_approval_and_rechecks():
    source = SKILL_MD.read_text(encoding="utf-8-sig")
    expected_commands = {
        "No internet": (
            "Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,IPv4Connectivity,IPv6Connectivity",
            "Resolve-DnsName www.microsoft.com | Select-Object Name,Type,IPAddress",
            "Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -InformationLevel Quiet",
            "Clear-DnsClientCache -WhatIf",
            "Clear-DnsClientCache",
        ),
        "Printer stuck": (
            "Get-Service -Name Spooler | Select-Object Name,Status,StartType",
            "Get-Printer | Select-Object Name,PrinterStatus,WorkOffline",
            "Get-PrintJob -PrinterName 'Microsoft Print to PDF' | Select-Object PrinterName,ID,DocumentName,JobStatus",
            "Get-PrintJob -PrinterName 'OneNote (Desktop)' | Select-Object PrinterName,ID,DocumentName,JobStatus",
            "Resume-PrintJob -PrinterName 'Microsoft Print to PDF' -ID 4294967295 -WhatIf",
            "Resume-PrintJob -PrinterName '<same printer>' -ID <same job ID>",
            "Suspend-PrintJob -PrinterName '<same printer>' -ID <same job ID>",
        ),
        "Slow PC": (
            r"Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3",
            "Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize,LastBootUpTime",
            "Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 Name,Id,CPU,WorkingSet64,Responding",
            r"Set-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name MinAnimate -Value '0' -WhatIf",
        ),
        "Disk full": (
            'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,FileSystem,FreeSpace,Size',
            "Get-ChildItem -LiteralPath $env:TEMP -File -Force | Measure-Object -Property Length -Sum",
            'compact.exe /C /S:"<same folder>"',
            'compact.exe /U /S:"<same folder>"',
        ),
        "Program frozen": (
            "Get-Process | Where-Object { -not $_.Responding } | Select-Object Name,Id,Responding,StartTime",
            "Task Manager → End task",
        ),
    }

    for title, commands in expected_commands.items():
        match = re.search(
            rf"^### {re.escape(title)} \(Windows-only\)\n(.*?)(?=^### |\Z)",
            source,
            re.M | re.S,
        )
        assert match is not None, title
        section = match.group(1)
        for phrase in (
            "Confirm the symptom",
            "Read-only diagnostics",
            "Facts.",
            "Uncertainty.",
            "One reversible repair",
            "one F2 approval",
            "Recheck and outcome",
            "Before",
            "After",
            "fixed",
            "not fixed",
            "Linux read-only equivalent",
            "hands_checkup",
        ):
            assert phrase.casefold() in section.casefold(), (title, phrase)
        for command in commands:
            assert command in section, (title, command)

    normalized = " ".join(source.split())
    assert "local Windows PowerShell session" in normalized
    assert "blocks pipelines and shell composition" in normalized
    assert "keep its `facts` and `inferences` separate" in normalized.casefold()
    assert "wait for it" in normalized
    assert "a second dangerous-command prompt" in normalized
    assert "Clearing a print job requires administrator privileges" in normalized
    assert "Remove-Item -Recurse/-Force" in normalized
    assert "del /s /q" in normalized
    assert "taskkill /F" in normalized
    assert "Stop-Process -Force" in normalized


def _pane_pattern(name: str) -> re.Pattern[str]:
    """One of the pane's regexes for reading /hands output; written to mean the same in Python."""
    source = PLUGIN_JS.read_text(encoding="utf-8-sig")
    [pattern] = re.findall(rf"const {name} =\s*/(.+)/m;", source)
    return re.compile(pattern, re.M)


class CommandCtx(RegisterCtx):
    def register_command(self, name, handler, **kwargs):
        self.handler = handler


def test_the_pane_reads_the_hands_command_output(hands_db, monkeypatch):
    """The pane runs /hands through slash.exec as a Desktop session (source None, platform desktop)
    and reads the target and the pairing reply out of the command's text."""
    ctx = CommandCtx()
    commands.register_commands(ctx, has_seed=True)
    monkeypatch.setattr(commands.client, "state", lambda: {"relay": True, "devices": [], "alerts": []})
    store.set_session_target("k", "my laptop")
    refused = Device("box")
    store.record_seen(refused.device_id, policy_hash="changed")
    status = ctx.handler("", session_key="k", platform="desktop", source=None)
    assert "\n" in status  # an alert line follows the status line
    assert _pane_pattern("STATUS_TARGET").search(status).group(1) == "my laptop"
    assert _pane_pattern("STATUS_TARGET").search(
        ctx.handler("", session_key="", platform="desktop", source=None)
    ).group(1) == "server"

    pytest.importorskip("hermes_cli.config")
    monkeypatch.setenv("HERMES_HOME", str(hands_db))
    reply = ctx.handler("pair 'new pc'", session_key="k", platform="desktop", source=None)
    code = _pane_pattern("PAIR_CODE").search(reply).group(1)
    command = _pane_pattern("PAIR_COMMAND").search(reply).group(1)
    assert store.pairing_code_name(code) == "new pc"
    assert command.startswith("hermes-hands pair ") and command.endswith(f"--name 'new pc' --code={code}")


def test_the_pane_reads_a_status_line_that_carries_cause_lines(hands_db, monkeypatch):
    """A relay-down status puts its cause on the next line; the pane must still find the target."""
    ctx = CommandCtx()
    commands.register_commands(ctx, has_seed=True)

    def refuse():
        raise commands.client.HandsError("hands: the relay is not reachable.")

    monkeypatch.setattr(commands.client, "state", refuse)
    monkeypatch.setattr(commands.store, "relay_alive", lambda: False)
    store.set_session_target("k", "my laptop")
    status = ctx.handler("status", session_key="k", platform="desktop", source=None)
    first, cause = status.splitlines()[:2]
    assert first.startswith("Hands: relay down; target my laptop; ")
    assert cause.startswith("hands: the relay is not reachable")
    assert _pane_pattern("STATUS_TARGET").search(status).group(1) == "my laptop"


def test_the_relay_seed_setting_names_the_variable_the_plugin_reads(hands_db, monkeypatch):
    """The Plugins settings form shows the seed as set, and writes it where ``register()`` reads it."""
    pytest.importorskip("hermes_cli.plugins_settings")
    from hermes_cli.plugins_settings import plugin_settings_fields

    monkeypatch.setenv("HERMES_HOME", str(hands_db))
    monkeypatch.setenv("HANDS_RELAY_SEED", "ab" * 32)
    [seed] = [f for f in plugin_settings_fields("hermes-hands", PLUGIN_DIR) if f["key"] == "HANDS_RELAY_SEED"]
    assert seed["type"] == "secret"
    assert seed["env"] == "HANDS_RELAY_SEED"
    assert seed["has_value"] is True
