"""The catalog copy pins its plugin, documentation and image to one release commit."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "docs" / "CATALOG-ENTRY.draft.yaml"
PR_BODY = REPO / "docs" / "CATALOG-PR-BODY.draft.md"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RULE = "remove comment lines"


def _catalog_copy(draft: str) -> str:
    lines = []
    for line in draft.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith("sha: "):
            line = f'sha: "{COMMIT}"'
        lines.append(line.replace("{release_commit}", COMMIT))
    return "\n".join(lines) + "\n"


def test_the_documented_rule_leaves_a_clean_copy_with_three_matching_commit_pins():
    yaml = pytest.importorskip("yaml")
    draft = DRAFT.read_text(encoding="utf-8-sig")
    copy = _catalog_copy(draft)

    assert re.findall(r"(?m)^\s*#|\s#", copy) == []
    assert "FILL AT FREEZE" not in copy and "0" * 40 not in copy
    assert "never in this file" not in copy
    expected = yaml.safe_load(draft)
    expected["sha"] = COMMIT
    for key in ("docs_url", "image"):
        expected[key] = expected[key].replace("{release_commit}", COMMIT)
    assert yaml.safe_load(copy) == expected


def test_the_only_comment_outside_the_header_is_the_one_after_sha():
    draft = DRAFT.read_text(encoding="utf-8-sig").splitlines()
    body = [line for line in draft if not line.startswith("#")]

    assert [line for line in body if re.search(r"\s#", line)] == [
        line for line in body if line.startswith("sha: ")
    ]


def test_freeze_steps_are_in_the_draft_header_and_never_move_a_pushed_tag():
    text = " ".join(re.sub(r"(?m)^#", "", DRAFT.read_text(encoding="utf-8-sig")).split())

    assert RULE in text
    assert "docs_url" in text and "image" in text
    assert "0.2.1" in text
    assert "git tag -d" not in text
    assert "Release steps" not in PR_BODY.read_text(encoding="utf-8-sig")
