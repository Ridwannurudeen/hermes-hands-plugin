import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check-freeze.py"
DEVICE_COMMIT = "7e078a50d3a09066aa3e95c3c1a86a9ec221996b"
RELEASE_COMMIT = "a" * 40
ZEROS = "0" * 40


def _load():
    spec = importlib.util.spec_from_file_location("check_freeze", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_freeze = _load()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _catalog(sha=RELEASE_COMMIT, docs_ref=RELEASE_COMMIT, image_ref=RELEASE_COMMIT):
    return (
        f'name: hermes-hands\nversion: "0.2.1"\nsha: "{sha}"\n'
        f'docs_url: https://github.com/example/plugin/tree/{docs_ref}/hermes-hands#readme\n'
        f'image: https://raw.githubusercontent.com/example/plugin/{image_ref}/hermes-hands/assets/banner.png\n'
    )


@pytest.fixture
def repo(tmp_path):
    _write(tmp_path / "README.md", f'pipx install "git+https://example.invalid/x@{DEVICE_COMMIT}#subdirectory=device"\n')
    _write(tmp_path / "hermes-hands" / "README.md", "Install from the catalog once listed.\n")
    _write(tmp_path / "hermes-hands" / "plugin.yaml", 'name: hermes-hands\nversion: "0.2.1"\n')
    _write(tmp_path / "device" / "pyproject.toml", '[project]\nversion = "0.2.0"\n')
    _write(tmp_path / "docs" / "CATALOG-ENTRY.draft.yaml", _catalog())
    return tmp_path


def test_matching_release_pins_pass_without_a_tag_or_git_mutations(repo, capsys):
    assert check_freeze.placeholders(repo) == []
    assert check_freeze.main(repo) == 0
    assert "Freeze check passed for plugin 0.2.1." in capsys.readouterr().out


def test_draft_placeholders_are_confined_to_the_three_catalog_fields(repo, capsys):
    _write(repo / "docs" / "CATALOG-ENTRY.draft.yaml", _catalog(ZEROS, "{release_commit}", "{release_commit}"))
    assert check_freeze.placeholders(repo) == []
    assert check_freeze.main(repo) == 1
    errors = capsys.readouterr().err
    assert len(errors.splitlines()) == 3
    assert all(f"catalog {field}" in errors for field in ("sha", "docs_url", "image"))


@pytest.mark.parametrize(("relative", "text"), [
    ("README.md", ZEROS),
    ("hermes-hands/README.md", "FILL AT FREEZE"),
    ("docs/nested/notes.md", "{release_commit}"),
    ("docs/CATALOG-ENTRY.draft.yaml", "# FILL AT FREEZE"),
    ("docs/CATALOG-ENTRY.draft.yaml", "image: https://x.invalid/" + ZEROS),
])
def test_placeholders_outside_the_allowed_catalog_fields_are_reported(repo, relative, text):
    _write(repo / relative, text)
    found = check_freeze.placeholders(repo)
    assert len(found) == 1 and found[0].startswith(f"{relative}:"), found


@pytest.mark.parametrize("relative", ["README.md", "hermes-hands/README.md", "docs/nested/install.md"])
@pytest.mark.parametrize("ref", ["v0.2.0", DEVICE_COMMIT[:7], "f" * 40, ""])
def test_device_installs_reject_tags_short_shas_and_unverified_commits(repo, relative, ref):
    revision = "@" + ref if ref else ""
    _write(repo / relative, f'pipx install "git+https://example.invalid/x{revision}#subdirectory=device"\n')
    assert any(problem.startswith(f"{relative}:") for problem in check_freeze.placeholders(repo))


@pytest.mark.parametrize("field", ["sha", "docs_url", "image"])
@pytest.mark.parametrize("ref", ["v0.2.0", "abcdef0", "0" * 40, "b" * 40])
def test_catalog_pins_must_be_one_nonzero_full_commit(repo, field, ref):
    values = {"sha": RELEASE_COMMIT, "docs_ref": RELEASE_COMMIT, "image_ref": RELEASE_COMMIT}
    values[{"sha": "sha", "docs_url": "docs_ref", "image": "image_ref"}[field]] = ref
    _write(repo / "docs" / "CATALOG-ENTRY.draft.yaml", _catalog(**values))
    assert check_freeze.main(repo) == 1


@pytest.mark.parametrize("relative", ["hermes-hands/plugin.yaml", "docs/CATALOG-ENTRY.draft.yaml"])
def test_plugin_version_must_be_021(repo, relative):
    path = repo / relative
    _write(path, path.read_text(encoding="utf-8-sig").replace('version: "0.2.1"', 'version: "0.2.0"'))
    assert check_freeze.main(repo) == 1


def test_device_version_stays_020(repo):
    _write(repo / "device" / "pyproject.toml", '[project]\nversion = "0.2.1"\n')
    assert check_freeze.main(repo) == 1


@pytest.mark.parametrize("source", ["https://example.invalid/x", "example/plugin/hermes-hands"])
@pytest.mark.parametrize("ref", ["v0.2.0", "<commit>", "<release commit sha>"])
def test_plugin_install_commands_require_a_full_commit(repo, source, ref):
    _write(repo / "README.md", f"hermes plugins install {source} --ref {ref}\n")
    assert check_freeze.main(repo) == 1
    _write(repo / "README.md", f"hermes plugins install {source} --ref {RELEASE_COMMIT}\n")
    assert check_freeze.main(repo) == 0


def test_a_filled_catalog_copy_can_be_checked_without_editing_the_draft(repo, tmp_path):
    _write(repo / "docs" / "CATALOG-ENTRY.draft.yaml", _catalog(ZEROS, "{release_commit}", "{release_commit}"))
    copy = tmp_path / "upstream" / "hermes-hands.yaml"
    _write(copy, _catalog())
    assert check_freeze.main(repo, catalog=copy) == 0


def test_catalog_install_does_not_need_a_ref(repo):
    _write(repo / "README.md", "hermes plugins install hermes-hands\n")
    assert check_freeze.main(repo) == 0


def test_release_workflow_fills_only_a_temporary_catalog_and_checks_tag_commit(repo, tmp_path, monkeypatch):
    import os
    import textwrap

    import yaml

    workflow = yaml.safe_load((SCRIPT.parents[1] / ".github/workflows/tests.yml").read_text(encoding="utf-8-sig"))
    step = next(step for step in workflow["jobs"]["freeze"]["steps"] if step.get("name") == "Check release freeze")
    run = step["run"]
    assert 'git rev-parse "${GITHUB_REF}^{commit}"' in run
    assert 'test "$release_commit" = "$(git rev-parse HEAD)"' in run
    assert '--catalog "$RUNNER_TEMP/hermes-hands.yaml"' in run
    assert '--expected-sha "$release_commit"' in run
    draft = repo / "docs/CATALOG-ENTRY.draft.yaml"
    _write(draft, _catalog(ZEROS, "{release_commit}", "{release_commit}"))
    original = draft.read_bytes()
    monkeypatch.chdir(repo)
    monkeypatch.setenv("RELEASE_COMMIT", RELEASE_COMMIT)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    program = run.split("python - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
    exec(compile(textwrap.dedent(program), "release-workflow", "exec"), {"__name__": "__main__"})
    catalog = Path(os.environ["RUNNER_TEMP"]) / "hermes-hands.yaml"
    assert draft.read_bytes() == original
    assert check_freeze.main(repo, catalog=catalog, expected_sha=RELEASE_COMMIT) == 0
    assert check_freeze.main(repo, catalog=catalog, expected_sha="b" * 40) == 1
