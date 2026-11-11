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
LS_REMOTE = (
    'git ls-remote https://github.com/Ridwannurudeen/hermes-hands-plugin "refs/tags/v0.2.0^{}"'
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def test_every_git_plugin_install_is_pinned_to_a_commit_read_from_the_release_tag():
    """r5-critic-1: Hermes 0.23.0 takes only a 40 character commit for --ref and drops a tree ref."""
    found = 0
    for path in DOCS:
        text = _text(path)
        for match in re.finditer(r"hermes plugins install (?!hermes-hands\b)[^`\n]*", text):
            found += 1
            assert "--ref <commit>" in match.group(0), (path.name, match.group(0))
            assert LS_REMOTE in text, path.name
    assert found >= 3


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
