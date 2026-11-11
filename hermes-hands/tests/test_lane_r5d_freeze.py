import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check-freeze.py"
ZEROS = "0" * 40
CATALOG_SHA = f'sha: "{ZEROS}"  # FILL AT FREEZE: the commit the v0.2.0 tag points to\n'


def _load():
    spec = importlib.util.spec_from_file_location("check_freeze", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_freeze = _load()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path):
    _write(tmp_path / "README.md", 'pipx install "git+https://example.invalid/x@v0.2.0#subdirectory=device"\n')
    _write(tmp_path / "hermes-hands" / "README.md", "Install from the v0.2.0 tag.\n")
    _write(tmp_path / "hermes-hands" / "plugin.yaml", 'name: hermes-hands\nversion: "0.2.0"\n')
    _write(tmp_path / "docs" / "CATALOG-ENTRY.draft.yaml", f"# Only sha is filled at freeze.\nname: x\n{CATALOG_SHA}")
    _write(tmp_path / "docs" / "CATALOG-PR-BODY.draft.md", "Paste the results into the pull request.\n")
    return tmp_path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=Freeze Test", "-c", "user.email=freeze@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _committed(repo: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "release")
    return repo


def test_a_clean_tree_has_no_placeholders_and_the_catalog_sha_is_exempt(repo):
    assert check_freeze.placeholders(repo) == []
    assert check_freeze.release_tag(repo) == "v0.2.0"


@pytest.mark.parametrize(
    ("relative", "text"),
    [
        ("README.md", f"pipx install \"git+https://example.invalid/x@{ZEROS}#subdirectory=device\"\n"),
        ("hermes-hands/README.md", "FILL AT FREEZE: the release commit\n"),
        ("docs/CATALOG-PR-BODY.draft.md", "- Pinned commit: (FILL AT FREEZE)\n"),
        ("docs/nested/notes.md", f"blob/{ZEROS}/docs\n"),
        ("docs/CATALOG-ENTRY.draft.yaml", f"# FILL AT FREEZE: sha\nname: x\n{CATALOG_SHA}"),
        ("docs/CATALOG-ENTRY.draft.yaml", f"name: x\n{CATALOG_SHA}image: https://x.invalid/{ZEROS}/b.png\n"),
    ],
    ids=["readme_zeros", "plugin_readme_note", "pr_body_note", "nested_doc", "catalog_header", "catalog_image"],
)
def test_a_placeholder_outside_the_catalog_sha_field_is_reported(repo, relative, text):
    _write(repo / relative, text)

    found = check_freeze.placeholders(repo)

    assert len(found) == 1 and found[0].startswith(f"{relative}:"), found


def test_the_tag_check_needs_the_release_tag_on_head(repo):
    _committed(repo)
    assert check_freeze.tag_problem(repo, "v0.2.0") == "tag v0.2.0 does not exist in this checkout"
    assert check_freeze.main(repo) == 1

    _git(repo, "tag", "-a", "v0.2.0", "-m", "Hermes Hands 0.2.0")
    assert check_freeze.tag_problem(repo, "v0.2.0") is None
    assert check_freeze.main(repo) == 0

    _write(repo / "later.txt", "after the tag\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "after the tag")
    assert "not at HEAD" in check_freeze.tag_problem(repo, "v0.2.0")
    assert check_freeze.main(repo) == 1


def test_a_placeholder_fails_the_check_even_with_the_tag_on_head(repo):
    _committed(repo)
    _git(repo, "tag", "-a", "v0.2.0", "-m", "Hermes Hands 0.2.0")
    _write(repo / "docs" / "CATALOG-PR-BODY.draft.md", "FILL AT FREEZE\n")

    assert check_freeze.main(repo) == 1


def test_a_placeholder_in_the_tagged_commit_fails_after_the_working_tree_is_cleaned(repo, capsys):
    """r5-release-1: the check reads the files from the tag, not from the checkout."""
    _committed(repo)
    clean = (repo / "README.md").read_text(encoding="utf-8-sig")
    _write(repo / "README.md", clean + "FILL AT FREEZE leftover\n")
    _git(repo, "commit", "-q", "-am", "leftover")
    _git(repo, "tag", "-a", "v0.2.0", "-m", "Hermes Hands 0.2.0")
    _write(repo / "README.md", clean)

    assert check_freeze.main(repo) == 1
    errors = capsys.readouterr().err
    assert "v0.2.0:README.md:2: FILL AT FREEZE leftover" in errors


def test_a_working_tree_that_differs_from_the_tag_fails(repo, capsys):
    _committed(repo)
    _git(repo, "tag", "-a", "v0.2.0", "-m", "Hermes Hands 0.2.0")
    _write(repo / "hermes-hands" / "README.md", "Install from the v0.2.0 tag. Edited after the tag.\n")

    assert check_freeze.main(repo) == 1
    assert "differ from tag v0.2.0" in capsys.readouterr().err


def test_an_untracked_doc_after_the_tag_fails(repo, capsys):
    _committed(repo)
    _git(repo, "tag", "-a", "v0.2.0", "-m", "Hermes Hands 0.2.0")
    _write(repo / "docs" / "NEW.md", "Not in the tag.\n")

    assert check_freeze.main(repo) == 1
    assert "docs/NEW.md" in capsys.readouterr().err
