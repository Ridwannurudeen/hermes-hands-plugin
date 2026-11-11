#!/usr/bin/env python3
"""Release freeze check. Run it after creating the release tag and before opening the catalog
pull request; the plugin tests workflow runs it on every v* tag push.

Reads README.md, hermes-hands/README.md and docs/ as they are in the tag v<plugin version>, not as
they are in the checkout. Fails while a placeholder (40 zeros or FILL AT FREEZE) is left in those
files, apart from the sha field of docs/CATALOG-ENTRY.draft.yaml: that commit is filled in only
in the hermes-agent copy, because a commit cannot hold its own hash. Also fails unless the tag
exists and points at HEAD, and when those files in the checkout differ from the tag.

Usage:
    python scripts/check-freeze.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLACEHOLDERS = ("0" * 40, "FILL AT FREEZE")
CATALOG = "docs/CATALOG-ENTRY.draft.yaml"
CHECKED = ("README.md", "hermes-hands/README.md", "docs")


def _scan(name: str, text: str, label: str) -> list[str]:
    found = []
    for number, line in enumerate(text.removeprefix("\ufeff").splitlines(), 1):
        if name == CATALOG and line.startswith("sha: "):
            continue
        if any(placeholder in line for placeholder in PLACEHOLDERS):
            found.append(f"{label}:{number}: {line.strip()}")
    return found


def placeholders(repo: Path) -> list[str]:
    """``path:line: text`` for every placeholder in the checkout outside the catalog draft's sha field."""
    paths = [repo / "README.md", repo / "hermes-hands" / "README.md"]
    paths += sorted(path for path in (repo / "docs").rglob("*") if path.is_file())
    found = []
    for path in paths:
        name = path.relative_to(repo).as_posix()
        found += _scan(name, path.read_text(encoding="utf-8-sig"), name)
    return found


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, encoding="utf-8", check=check)


def tagged_placeholders(repo: Path, tag: str) -> list[str]:
    """``tag:path:line: text`` for every placeholder in the tagged files outside the catalog sha field."""
    names = _git(repo, "ls-tree", "-r", "--name-only", tag, "--", *CHECKED).stdout.splitlines()
    found = []
    for name in names:
        found += _scan(name, _git(repo, "show", f"{tag}:{name}").stdout, f"{tag}:{name}")
    return found


def tree_problem(repo: Path, tag: str) -> str | None:
    changed = _git(repo, "diff", "--name-only", tag, "--", *CHECKED).stdout.splitlines()
    changed += _git(repo, "ls-files", "--others", "--exclude-standard", "--", *CHECKED).stdout.splitlines()
    if changed:
        return f"these files differ from tag {tag}: {', '.join(sorted(set(changed)))}"
    return None


def release_tag(repo: Path) -> str:
    text = (repo / "hermes-hands" / "plugin.yaml").read_text(encoding="utf-8-sig")
    return "v" + re.search(r'^version: "([^"]+)"', text, re.MULTILINE).group(1)


def _commit(repo: Path, name: str) -> str | None:
    result = _git(repo, "rev-parse", "--verify", "--quiet", f"{name}^{{commit}}", check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def tag_problem(repo: Path, tag: str) -> str | None:
    tagged = _commit(repo, f"refs/tags/{tag}")
    if tagged is None:
        return f"tag {tag} does not exist in this checkout"
    head = _commit(repo, "HEAD")
    if tagged != head:
        return f"tag {tag} points at {tagged}, not at HEAD ({head})"
    return None


def main(repo: Path = REPO) -> int:
    tag = release_tag(repo)
    if _commit(repo, f"refs/tags/{tag}") is None:
        problems = placeholders(repo)
    else:
        problems = tagged_placeholders(repo, tag)
        problem = tree_problem(repo, tag)
        if problem is not None:
            problems.append(problem)
    problem = tag_problem(repo, tag)
    if problem is not None:
        problems.append(problem)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"Freeze check passed for {tag}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
