"""Cheap checks on the public docs: no private details, no dashes or smart quotes, and install and
pairing lines that the current code accepts."""

import ast
import importlib.util
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCS = sorted(
    [REPO / "README.md", REPO / "hermes-hands" / "README.md"]
    + [path for path in (REPO / "docs").iterdir() if path.suffix in (".md", ".yaml")]
)
# Built from pieces so this file does not match itself.
PRIVATE = ("hands." + "gud" + "man", "gud" + "ma", "/mnt/c/" + "Users/", "for " + "Ridwan to post")
TYPOGRAPHY = ("–", "—", "‘", "’", "“", "”", "→", "…")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("path", DOCS, ids=lambda path: path.relative_to(REPO).as_posix())
def test_public_docs_hold_no_private_host_user_path_or_internal_note(path):
    text = _text(path)

    assert [needle for needle in PRIVATE if needle.casefold() in text.casefold()] == []


@pytest.mark.parametrize("path", DOCS, ids=lambda path: path.relative_to(REPO).as_posix())
def test_public_docs_use_plain_ascii_punctuation(path):
    text = _text(path)

    assert [char for char in TYPOGRAPHY if char in text] == []


def test_no_doc_names_the_removed_screen_extra():
    workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    for path in DOCS + workflows:
        text = _text(path)
        assert re.findall(r"\[[a-z,]*screen[a-z,]*\]|screen extra|`screen` extra", text) == [], path.name


def test_every_documented_pair_command_carries_the_owner_label():
    for path in DOCS:
        for match in re.finditer(r"(?:/hands pair|hermes hands pair) [^`\n]*", _text(path)):
            assert "--owner-label" in match.group(0), (path.name, match.group(0))


def test_receipt_verification_on_another_computer_uses_the_equals_key_form():
    text = _text(REPO / "README.md")

    assert "hermes-hands receipt verify" in text
    assert "--key=" in text and "--key " not in text


def test_the_catalog_draft_declares_what_the_manifest_declares():
    yaml = pytest.importorskip("yaml")
    entry = yaml.safe_load(_text(REPO / "docs" / "CATALOG-ENTRY.draft.yaml"))
    manifest = yaml.safe_load(_text(REPO / "hermes-hands" / "plugin.yaml"))
    capabilities = entry["capabilities"]

    assert entry["name"] == manifest["name"]
    assert entry["version"] == manifest["version"]
    assert entry["requires_hermes"] == manifest["requires_hermes"]
    for key in ("provides_tools", "provides_hooks", "provides_middleware", "requires_env"):
        assert sorted(capabilities.get(key) or []) == sorted(manifest.get(key) or []), key
    assert f"/v{manifest['version']}/" in entry["docs_url"] and f"/v{manifest['version']}/" in entry["image"]


def test_no_doc_says_the_device_package_is_already_on_pypi():
    for path in DOCS:
        text = _text(path)
        assert re.findall(r"published on PyPI|on PyPI as|package on PyPI|PyPI package", text) == [], path.name


def test_the_first_device_install_is_the_git_install_at_the_release_tag():
    """r4-release-1: a commit cannot hold its own hash, so the docs install from the release tag and
    only the catalog copy in hermes-agent names the commit."""
    yaml = pytest.importorskip("yaml")
    version = yaml.safe_load(_text(REPO / "hermes-hands" / "plugin.yaml"))["version"]
    expected = f"git+https://github.com/Ridwannurudeen/hermes-hands-plugin@v{version}#subdirectory=device"
    for path in (REPO / "README.md", REPO / "hermes-hands" / "README.md", REPO / "docs" / "CATALOG-PR-BODY.draft.md"):
        text = _text(path)
        installs = re.findall(r'pipx install "([^"]+)"', text)
        assert installs and installs[0] == expected, (path.name, installs[:1])
        assert set(re.findall(r"git\+https://[^\"`\s]+", text)) == {expected}, path.name


def test_the_catalog_sha_is_the_only_placeholder_left_in_the_docs():
    """r4-release-2: the freeze check finds nothing outside the catalog draft's sha field."""
    yaml = pytest.importorskip("yaml")
    spec = importlib.util.spec_from_file_location("check_freeze", REPO / "scripts" / "check-freeze.py")
    check_freeze = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check_freeze)
    draft = _text(REPO / "docs" / "CATALOG-ENTRY.draft.yaml")

    assert check_freeze.placeholders(REPO) == []
    assert yaml.safe_load(draft)["sha"] == "0" * 40
    assert [line for line in draft.splitlines() if "FILL AT FREEZE" in line or "0" * 40 in line] == [
        line for line in draft.splitlines() if line.startswith("sha: ")
    ]


def test_docs_name_every_source_of_the_other_hook_block_and_its_remedy():
    for path in DOCS:
        text = _text(path)
        if "hermes plugins disable" in text:
            assert "hooks.outbound" in text and "hermes hooks list" in text, path.name


def test_docs_do_not_say_all_startup_persistence_is_blocked():
    for path in DOCS:
        assert re.findall(r"(?i)(?<!common )\bstartup persistence\b", _text(path)) == [], path.name
    readme = _text(REPO / "README.md")
    for passes in ("UserInitMprLogonScript", "AutoRun", "sc create"):
        assert passes in readme, passes


def _console_sentences(path: Path, function: str, constants: tuple[str, ...] = ()) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function:
            for call in ast.walk(node):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "write"
                    and call.args
                    and isinstance(call.args[0], ast.Constant)
                ):
                    found.add(call.args[0].value)
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in constants for target in node.targets
        ):
            found.update(item.value for item in ast.walk(node.value) if isinstance(item, ast.Constant))
    return {sentence.strip() for sentence in found if isinstance(sentence, str) and sentence.strip()}


def test_readme_quotes_every_help_result_the_console_can_print():
    device = REPO / "device" / "hermeshands_device"
    sentences = _console_sentences(
        device / "loop.py", "_send_help_request", ("_HELP_REFUSALS", "_HELP_NOT_ACCEPTED")
    ) | _console_sentences(device / "console.py", "_edit_help")
    sentences -= {"owner_origin_required", "help_disabled", "rate_limited"}
    readme = _text(REPO / "README.md")

    assert len(sentences) >= 10
    assert sorted(sentence for sentence in sentences if sentence not in readme) == []
