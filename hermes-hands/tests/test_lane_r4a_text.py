import pytest

from hands_fakes import PLUGIN_DIR

TYPOGRAPHY = ("–", "—", "‘", "’", "“", "”", "→", "…")


@pytest.mark.parametrize("name", ["desktop/plugin.js", "skills/hands/SKILL.md", "plugin.yaml"])
def test_shipped_text_uses_plain_ascii_punctuation(name):
    """r3-docs-ci-6: the Desktop pane, the skill and the manifest reach people too."""
    text = (PLUGIN_DIR / name).read_text(encoding="utf-8-sig")

    assert [char for char in TYPOGRAPHY if char in text] == []


def test_the_manifest_scopes_the_approval_rule_to_witness_sessions():
    """r3-relay-skill-2: outside a witness session nothing asks the helper (witness.py)."""
    source = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8-sig")
    description = " ".join(
        source.split("description: >", 1)[1].split("requires_hermes:", 1)[0].split()
    )

    assert (
        "In a witness session the gateway asks the helper to approve every tool call that reaches "
        "the device." in description
    )
    assert ". The gateway asks the helper to approve every tool call" not in description
