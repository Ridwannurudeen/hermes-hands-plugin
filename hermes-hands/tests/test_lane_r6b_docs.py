"""Round-6 doc checks: the gateway install is pinned, the CI claim matches the workflow, and the
catalog and pull request disclosures name the stalled watcher gap that the README names."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"
DOCS = sorted(
    [README, REPO / "hermes-hands" / "README.md"]
    + [path for path in (REPO / "docs").iterdir() if path.suffix in (".md", ".yaml")]
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def test_plugin_install_guidance_uses_the_catalog_once_listed():
    for path in (README, REPO / "hermes-hands" / "README.md"):
        text = _text(path)
        assert "Once Hermes Hands is listed in the plugin catalog" in text
        assert "hermes plugins install hermes-hands" in text
        assert "refs/tags/v0.2.0" not in text
        assert "--ref <" not in text


def test_docs_hold_no_unreviewed_windows_installer_or_pypi_alternative():
    for path in DOCS:
        text = _text(path)
        assert "scripts/windows" not in text
        assert "Install-HermesHands" not in text
        assert not re.search(r"(?:pipx|pip) install [\"']?hermes-hands", text)
        assert "hermes-hands[keyring]==" not in text


def test_private_surface_disclosures_name_the_posted_issue_and_unlisted_couplings():
    for path in (REPO / "docs" / "CATALOG-PR-BODY.draft.md", REPO / "docs" / "HOOK-REQUEST-ISSUE.md"):
        text = _text(path)
        assert "https://github.com/NousResearch/hermes-agent/issues/154264" in text
        for symbol in ("_run_bash", "_prepare_command", "_quote_cwd_for_cd", "_quote_shell_path", "_hermes_sandbox_home"):
            assert symbol in text
        for evidence in ("terminal_tool_backends.py:231", "terminal_tool_config.py:191", "file_tools.py:328-335", "file_tools_read_tracking.py:49", "file_tools_read_tracking.py:130"):
            assert evidence in text
        assert "has not been posted" not in text
        assert "has not been opened" not in text


def test_the_readme_names_every_python_version_the_device_ci_runs():
    """r5-release-2."""
    workflow = _text(REPO / ".github" / "workflows" / "device.yml")
    versions = re.findall(r'"(3\.\d+)"', re.search(r"python: \[([^\]]+)\]", workflow).group(1))
    claim = re.search(
        r"The device CI tests on Python ([^.]+(?:\.\d+[^.]*)*?) with", _text(README)
    ).group(1)

    assert re.findall(r"3\.\d+", claim) == versions
    assert "scripts/check-freeze.py" in _text(REPO / ".github" / "workflows" / "tests.yml")
    assert "release tag also runs `scripts/check-freeze.py`" in _text(README)


@pytest.mark.parametrize(
    "path",
    [
        README,
        REPO / "docs" / "CATALOG-ENTRY.draft.yaml",
        REPO / "docs" / "CATALOG-PR-BODY.draft.md",
    ],
    ids=lambda path: path.name,
)
def test_the_stalled_watcher_gap_is_disclosed_wherever_the_new_group_gap_is(path):
    """r5-release-6."""
    text = " ".join(_text(path).split())

    assert "new session or" in text
    assert "has died or stalled for more than a second" in text
