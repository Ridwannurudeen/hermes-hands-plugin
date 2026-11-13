#!/usr/bin/env python3
"""Check plugin 0.2.1 release pins and reviewed device installs without changing tags.

The checkout draft deliberately leaves sha, docs_url and image for the lead to fill in the
hermes-agent catalog copy after the release commit exists. Normal mode reports these three
fields until filled; --catalog checks that copy instead. All three must use the same full
commit SHA. The already published v0.2.0 tag stays unchanged.

Usage:
    python scripts/check-freeze.py
    python scripts/check-freeze.py --catalog path/to/plugin-catalog/hermes-hands.yaml
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLACEHOLDERS = ("0" * 40, "FILL AT FREEZE", "{release_commit}")
CATALOG = "docs/CATALOG-ENTRY.draft.yaml"
PLUGIN_VERSION = "0.2.1"
DEVICE_COMMIT = "7e078a50d3a09066aa3e95c3c1a86a9ec221996b"


def _scan(repo: Path, name: str, text: str, label: str) -> list[str]:
    found = []
    for number, line in enumerate(text.removeprefix("\ufeff").splitlines(), 1):
        if name == CATALOG and (
            line.startswith("sha: ")
            or (line.startswith(("docs_url: ", "image: ")) and "{release_commit}" in line and not any(value in line for value in PLACEHOLDERS[:2]))
        ):
            continue
        if any(placeholder in line for placeholder in PLACEHOLDERS):
            found.append(f"{label}:{number}: {line.strip()}")
            continue
        install = re.search(r"hermes plugins install\s+([^\s`]+)([^`\n]*)", line)
        if install is not None and ("/" in install.group(1) or "--ref" in install.group(2)):
            pin = re.search(r"--ref\s+([0-9a-f]{40})(?=\s|[\"'`]|$)", install.group(2))
            if pin is None or pin.group(1) == "0" * 40:
                found.append(f"{label}:{number}: plugin install must name a full 40 character commit SHA")
        for spec in re.findall(r"git\+https://[^\s\"'`]+#subdirectory=device", line):
            ref = spec.rsplit("@", 1)[-1].split("#", 1)[0]
            if re.fullmatch(r"[0-9a-f]{40}", ref) is None:
                found.append(f"{label}:{number}: device install must name a full 40 character commit SHA: {spec}")
            elif ref != DEVICE_COMMIT:
                found.append(f"{label}:{number}: device install must pin the reviewed commit {DEVICE_COMMIT}: {spec}")
    return found


def placeholders(repo: Path) -> list[str]:
    """Report checkout placeholders outside the catalog draft fields and invalid install refs."""
    paths = [repo / "README.md", repo / "hermes-hands" / "README.md"]
    paths += sorted(path for path in (repo / "docs").rglob("*") if path.is_file())
    found = []
    for path in paths:
        name = path.relative_to(repo).as_posix()
        found += _scan(repo, name, path.read_text(encoding="utf-8-sig"), name)
    return found


def _field(text: str, name: str) -> str:
    match = re.search(rf"^{name}:\s*[\"']?([^\n\"']+)", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def catalog_problems(path: Path, expected_sha: str | None = None) -> list[str]:
    text = path.read_text(encoding="utf-8-sig")
    sha = _field(text, "sha")
    found = []
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None or sha == "0" * 40:
        found.append("catalog sha: set the full 40 character release commit SHA")
    if expected_sha is not None and (re.fullmatch(r"[0-9a-f]{40}", expected_sha) is None or sha != expected_sha):
        found.append("catalog sha: must equal the tagged release commit SHA")
    for field, pattern in (
        ("docs_url", r"https://github\.com/[^/]+/[^/]+/tree/([0-9a-f]{40})/hermes-hands#readme"),
        ("image", r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/([0-9a-f]{40})/hermes-hands/assets/banner\.png"),
    ):
        match = re.fullmatch(pattern, _field(text, field))
        if match is None or match.group(1) != sha or sha == "0" * 40:
            found.append(f"catalog {field}: set its commit to the same full release SHA as catalog sha")
    if _field(text, "version") != PLUGIN_VERSION:
        found.append(f"catalog version must be {PLUGIN_VERSION}")
    return found


def main(repo: Path = REPO, catalog: Path | None = None, expected_sha: str | None = None) -> int:
    problems = placeholders(repo)
    manifest = (repo / "hermes-hands" / "plugin.yaml").read_text(encoding="utf-8-sig")
    if _field(manifest, "version") != PLUGIN_VERSION:
        problems.append(f"plugin version must be {PLUGIN_VERSION}")
    device = tomllib.loads((repo / "device" / "pyproject.toml").read_text(encoding="utf-8-sig"))
    if device["project"]["version"] != "0.2.0":
        problems.append("device version must remain 0.2.0")
    problems += catalog_problems(catalog if catalog is not None else repo / CATALOG, expected_sha)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"Freeze check passed for plugin {PLUGIN_VERSION}.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, help="filled catalog copy to check instead of the draft")
    parser.add_argument("--expected-sha", help="require the catalog SHA to match this tagged release commit")
    args = parser.parse_args()
    sys.exit(main(catalog=args.catalog, expected_sha=args.expected_sha))
