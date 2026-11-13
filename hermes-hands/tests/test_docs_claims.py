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
    assert manifest["requires_hermes"] == ">=0.23.1"
    for key in ("provides_tools", "provides_hooks", "provides_middleware", "requires_env"):
        assert sorted(capabilities.get(key) or []) == sorted(manifest.get(key) or []), key
    assert entry["version"] == "0.2.1"
    assert "/{release_commit}/" in entry["docs_url"]
    assert "/{release_commit}/" in entry["image"]


def test_no_doc_says_the_device_package_is_already_on_pypi():
    for path in DOCS:
        text = _text(path)
        assert re.findall(r"published on PyPI|on PyPI as|package on PyPI|PyPI package", text) == [], path.name


def test_the_first_device_install_is_the_git_install_at_the_reviewed_commit():
    """Device installs use the full commit whose device code the maintainers reviewed."""
    expected = "git+https://github.com/Ridwannurudeen/hermes-hands-plugin@7e078a50d3a09066aa3e95c3c1a86a9ec221996b#subdirectory=device"
    for path in (REPO / "README.md", REPO / "hermes-hands" / "README.md", REPO / "docs" / "CATALOG-PR-BODY.draft.md"):
        text = _text(path)
        installs = re.findall(r'pipx install "([^"]+)"', text)
        assert installs and installs[0] == expected, (path.name, installs[:1])
        assert set(re.findall(r"git\+https://[^\"`\s]+", text)) == {expected}, path.name


def test_every_device_install_uses_a_full_commit_sha():
    paths = DOCS + sorted(path for path in (REPO / "scripts").rglob("*") if path.is_file())
    installs = []
    for path in paths:
        if path.suffix not in (".md", ".yaml", ".py", ".ps1", ".cmd", ".sh"):
            continue
        for spec in re.findall(r"git\+https://[^\s\"'`]+#subdirectory=device", _text(path)):
            ref = spec.rsplit("@", 1)[-1].split("#", 1)[0]
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (path.name, spec)
            installs.append(spec)
    assert installs


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


def test_witness_docs_disclose_the_runtime_envelope_and_replace_all_exception():
    paths = [
        REPO / "README.md",
        REPO / "hermes-hands" / "README.md",
        REPO / "hermes-hands" / "skills" / "hands" / "SKILL.md",
        REPO / "docs" / "CATALOG-PR-BODY.draft.md",
        REPO / "docs" / "CATALOG-ENTRY.draft.yaml",
    ]
    for path in paths:
        text = _text(path)
        assert "replace_all" in text, path.name
        assert "one-time shell snapshot" in text, path.name
        assert "login" in text and "refresh" in text, path.name
        assert "approved command and file operations" in text, path.name


def test_hook_request_describes_current_public_api_workarounds():
    text = _text(REPO / "docs" / "HOOK-REQUEST-ISSUE.md")
    assert "_configured_terminal_cwd" not in text
    assert "cannot prove a patch's content" not in text
    assert "`keyboard.txt` is refused" not in text
    assert "re-reads" in text and "backoff" in text


def test_catalog_pr_discloses_exact_core_text_coupling_and_test_matrix():
    text = _text(REPO / "docs" / "CATALOG-PR-BODY.draft.md")
    assert "matches core's generated command text exactly" in text
    assert "fails closed when core's text changes" in text
    assert "CI covers Hermes 0.23.1" in text
    assert "regression matrix covers Hermes 0.23.0" not in text


@pytest.mark.parametrize("relative", ["README.md", "hermes-hands/README.md", "docs/CATALOG-PR-BODY.draft.md", "docs/CATALOG-ENTRY.draft.yaml"])
def test_release_docs_disclose_whole_document_transfer_and_supported_ci(relative):
    text = _text(REPO / relative)
    assert "whole file to the gateway" in text
    assert "even when a page" in text
    assert "console shows" in text
    assert "before the first terminal or file-tool execution" in text
    assert "declined or refused" in text
    assert "pending" in text
    assert not re.search(r"0\.23\.0.{0,100}(regression|matrix)|regression.{0,100}0\.23\.0", text)
    assert "A refused read or search returns Hands' own message" not in text


def test_catalog_pr_marks_the_posted_hook_request_as_pending_release_update():
    text = _text(REPO / "docs/CATALOG-PR-BODY.draft.md")
    assert "lead will update" in text
    assert "docs/HOOK-REQUEST-ISSUE.md" in text
    assert "Every coupling, with the public seam that would replace it, is listed in [the posted" not in text


@pytest.mark.parametrize("relative", ["README.md", "hermes-hands/README.md", "docs/CATALOG-ENTRY.draft.yaml"])
def test_terminal_default_is_explicit_in_approval_and_dispatch(relative):
    text = _text(REPO / relative)
    assert re.search(r"omitted or null terminal `?timeout`?", text)
    assert "public configuration bridge (180 seconds when unset)" in text
    assert "shown on the approval card and dispatched unchanged" in text
    assert "Preserving the scoped profile default needs a public accessor" in text
    hook = _text(REPO / "docs/HOOK-REQUEST-ISSUE.md")
    assert "public effective-timeout read" in hook
    assert "tools/terminal_tool_config.py:270-277" in hook
    assert "tools/terminal_scope.py:81-86" in hook


@pytest.mark.parametrize("relative", ["README.md", "hermes-hands/README.md", "docs/CATALOG-PR-BODY.draft.md"])
def test_core_masked_annotation_refusal_is_documented_honestly(relative):
    text = _text(REPO / relative)
    assert "Text Hermes would mask on the approval card is refused" in text
    assert "never sees different text from what runs" in text
    assert "`token: Optional[str]`" in text
    assert 'Witness calls refuse text Hermes would mask, non-placeholder quoted credential values, token prefixes, Bearer values, key blocks, password flags, credential URLs and long or high-entropy values, including beyond a write preview; plain words and keyword arguments in a recognised source file, with or without spaces around `=`, are treated as variable references unless another refusal rule matches; in other files and in terminal commands, a bare word assigned to a secret-looking name is refused. Shell files (`.sh`, `.bash`, `.zsh`) still refuse no-space assignments, as do environment-lookup lookalikes such as `os.environXYZ123`.' in text


def test_witness_destination_and_media_docs_match_execution():
    text = _text(REPO / "README.md")
    assert "outside witness mode a `terminal.cwd` configured on the gateway still wins" in text
    assert "approved relative destination stays bound to the device folder" in text
    assert "A MEDIA line cannot fetch device files during a witness session" in text
    assert "approved screenshots already cached on the gateway remain deliverable" in text


@pytest.mark.parametrize("relative", [
    "README.md", "hermes-hands/README.md", "docs/CATALOG-PR-BODY.draft.md",
    "docs/HOOK-REQUEST-ISSUE.md", "hermes-hands/skills/hands/SKILL.md",
])
def test_credential_docs_describe_context_and_the_source_word_limit(relative):
    text = " ".join(_text(REPO / relative).split())
    assert "in other files and in terminal commands, a bare word assigned to a secret-looking name is refused" in text
    assert "plain words and keyword arguments in a recognised source file, with or without spaces around `=`, are treated as variable references" in text
    assert "Shell files (`.sh`, `.bash`, `.zsh`) still refuse no-space assignments" in text
    assert "environment-lookup lookalikes" in text
    assert "The source-file rule is based on the file extension, so text that looks like configuration inside a source file is treated as source." in text
    assert "Keyword arguments whose value is a bare name" in text
    assert "the spaced form `password = True` works" in text
    assert "`Client(token = token, api_key = api_key)` is still masked and refused" in text
    assert "credential literals remain refused" not in text
    assert "Literal credentials remain refused" not in text


@pytest.mark.parametrize("relative", [
    "README.md", "hermes-hands/README.md", "docs/CATALOG-PR-BODY.draft.md",
])
def test_background_docs_disclose_no_runtime_deadline(relative):
    text = _text(REPO / relative)
    assert "`timeout` for a foreground command" in text
    assert "background command has no time limit" in text
    assert "leave out `timeout`; press S to stop it" in text
    assert "`background=true`" in text


def test_retention_and_refusal_docs_do_not_overstate_the_guarantee():
    pr = _text(REPO / "docs/CATALOG-PR-BODY.draft.md")
    assert "screenshots older than 24 hours are removed when another capture occurs" in pr
    assert "cached on the gateway for up to 24 hours" not in pr
    assert "up to 7 days" not in pr
    assert "cleanup runs when `serve` starts and then hourly while it runs" in pr
    skill = " ".join(_text(REPO / "hermes-hands/skills/hands/SKILL.md").split())
    assert "nothing ran anywhere" not in skill
    assert "the refused command did not run" in skill
    assert "earlier steps of the same tool call" in skill
    assert "write before its lint check" in skill


@pytest.mark.parametrize("relative", ["docs/CATALOG-PR-BODY.draft.md", "docs/HOOK-REQUEST-ISSUE.md"])
def test_redactor_import_docs_name_its_current_function(relative):
    text = _text(REPO / relative)
    assert "inside `_secret_problem`" in text
    assert "inside `_contains_secret`" not in text
