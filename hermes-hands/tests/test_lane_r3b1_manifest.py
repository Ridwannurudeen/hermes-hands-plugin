import pytest

from hands_fakes import PLUGIN_DIR

MANIFEST = PLUGIN_DIR / "plugin.yaml"


def test_plugin_validate_admits_the_plugin_directory(tmp_path, monkeypatch):
    """The catalog admission check and the CI step `plugins validate` run this validator."""
    plugin_validate = pytest.importorskip("hermes_cli.plugin_validate")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    report = plugin_validate.validate_plugin_dir(PLUGIN_DIR)

    assert report.ok, report.failures
    assert ("declared middleware", True, "matches registrations") in report.checks


def test_manifest_declares_the_middleware_and_describes_the_approval_rule():
    source = MANIFEST.read_text(encoding="utf-8-sig")
    description = " ".join(
        source.split("description: >", 1)[1].split("requires_hermes:", 1)[0].split()
    )

    assert "provides_middleware: [tool_execution]" in source.splitlines()
    assert "read-only list" not in description
    assert "300 character" not in description
    assert (
        "In a witness session the gateway asks the helper to approve every tool call that reaches the device"
        in description
    )
    assert [char for char in source if ord(char) > 127] == []
