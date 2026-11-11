from hands import messages


def test_a_failed_capture_says_nothing_was_captured_and_allows_a_later_try():
    text = messages.device_result_error("screenshot_failed", "laptop")

    assert text == "laptop could not capture the screen right now. Nothing was captured. Try again in a minute."
    assert "retry" not in text


def test_the_upgrade_hint_reaches_the_protocol_mismatch_reply():
    assert messages.protocol_mismatch("hands/0") == f"hands: the device speaks hands/0. {messages.UPGRADE}"


def test_the_persistence_refusal_names_systemd_user_units_and_login_folders():
    text = messages.WITNESS_AUTOSTART_BLOCKED

    assert "systemd user units and login folders" in text
    for words in ("30 minute", "Run keys", "scheduled tasks", "startup", "shell profiles"):
        assert words in text
