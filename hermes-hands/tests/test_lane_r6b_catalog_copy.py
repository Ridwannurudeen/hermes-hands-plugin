"""r5-release-4: the hermes-agent copy of the catalog draft carries no freeze notes. The freeze steps
say: delete every line that starts with #, put the commit in sha and delete the comment after it."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "docs" / "CATALOG-ENTRY.draft.yaml"
PR_BODY = REPO / "docs" / "CATALOG-PR-BODY.draft.md"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RULE = "delete every line that starts with #"


def _catalog_copy(draft: str) -> str:
    lines = []
    for line in draft.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith("sha: "):
            line = f'sha: "{COMMIT}"'
        lines.append(line)
    return "\n".join(lines) + "\n"


def test_the_documented_rule_leaves_a_clean_copy_that_differs_only_in_sha():
    yaml = pytest.importorskip("yaml")
    draft = DRAFT.read_text(encoding="utf-8-sig")
    copy = _catalog_copy(draft)

    assert re.findall(r"(?m)^\s*#|\s#", copy) == []
    assert "FILL AT FREEZE" not in copy and "0" * 40 not in copy
    assert "never in this file" not in copy
    expected = yaml.safe_load(draft)
    expected["sha"] = COMMIT
    assert yaml.safe_load(copy) == expected


def test_the_only_comment_outside_the_header_is_the_one_after_sha():
    draft = DRAFT.read_text(encoding="utf-8-sig").splitlines()
    body = [line for line in draft if not line.startswith("#")]

    assert [line for line in body if re.search(r"\s#", line)] == [
        line for line in body if line.startswith("sha: ")
    ]


@pytest.mark.parametrize("path", [DRAFT, PR_BODY], ids=lambda path: path.name)
def test_the_freeze_steps_name_the_copy_rule_and_the_tag_retry(path):
    text = " ".join(re.sub(r"(?m)^#", "", path.read_text(encoding="utf-8-sig")).split())

    assert RULE in text
    assert "delete the comment after it" in text
    assert "git tag -d v0.2.0" in text
    assert "v0.2.1" in text
    assert "Nothing else in the copy changes" not in text
