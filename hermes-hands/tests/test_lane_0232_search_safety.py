"""Option-shaped search patterns are refused before approval or execution."""

import pytest

pytest.importorskip("tools.environments.base")

from hands import environment  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401


@pytest.mark.parametrize("pattern", ["--pre=/tmp/x.sh", "-f/etc/passwd", "-e", "-"])
@pytest.mark.parametrize("target", ["content", "files"])
def test_leading_dash_search_never_gets_a_card_or_job(dispatch, monkeypatch, pattern, target):
    d = dispatch
    commands = []

    def execute(env, command, cwd="", **kwargs):
        commands.append(command)
        return {"output": "stopped by test", "returncode": 255}

    monkeypatch.setattr(environment.HandsEnvironment, "execute", execute)
    before = d.files()
    result = d.invoke("search_files", {"path": f"{d.base}/work", "pattern": pattern, "target": target})
    assert "search patterns starting with - are refused: drop the leading dash or search for it another way" in result
    assert d.cards == [] and d.answers == [] and d.jobs == []
    assert commands == [] and d.files() == before
