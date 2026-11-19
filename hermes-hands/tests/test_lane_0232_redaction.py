"""Witness decisions follow the installed core's forced redactor at call time."""

import pytest

from hands import messages, witness


@pytest.mark.parametrize("text", [
    "password=True", "password=False", "password=None",
    "token = abc123def456", "token = 0x1234567890abcdef1234567890",
    'password = "hunter2"', "ya29." + "a" * 30,
])
def test_core_masked_values_are_never_approved(text):
    from agent.redact import redact_sensitive_text

    problem = witness._secret_problem(text, source=True)
    if redact_sensitive_text(text, force=True) != text:
        assert problem == messages.WITNESS_SECRET_HIDDEN
    elif text.startswith(("password=", "token =")):
        assert problem is None
    else:
        assert problem == messages.WITNESS_SECRET_BLOCKED


def test_spacing_probe_is_forced_even_when_compact_value_is_not_masked(monkeypatch):
    from agent import redact

    calls = []

    def mask_spaced(text, *, force=False):
        calls.append((text, force))
        return "password = ***" if text == "password = True" else text

    monkeypatch.setattr(redact, "redact_sensitive_text", mask_spaced)
    assert witness._secret_problem("password=True", source=True, spacing_hint=True) == messages.WITNESS_SECRET_HIDDEN
    assert ("password=True", True) in calls
    assert ("password = True", True) in calls


def test_redactor_policy_is_not_cached_between_calls(monkeypatch):
    from agent import redact

    monkeypatch.setattr(redact, "redact_sensitive_text", lambda text, *, force=False: text)
    assert witness._secret_problem("password=True", source=True) is None
    monkeypatch.setattr(redact, "redact_sensitive_text", lambda text, *, force=False: "***")
    assert witness._secret_problem("password=True", source=True) == messages.WITNESS_SECRET_HIDDEN
