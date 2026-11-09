from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path.home() / ".hermes-hands"
CONFIG_PATH = ROOT / "config.json"
POLICY_PATH = ROOT / "policy.json"
KEY_PATH = ROOT / "device.json"
OUT_DIR = ROOT / "out"


def load() -> dict:
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
    return {}


def save(data: dict) -> None:
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    if os.name != "nt":
        CONFIG_PATH.chmod(0o600)


def gateway_url() -> str:
    return load().get("gateway_url", "").rstrip("/")


def device_id() -> str:
    return load().get("device_id", "")


def relay_public_key() -> bytes:
    from .protocol import unb64u

    key = load().get("relay_public_key", "")
    return unb64u(key) if key else b""
