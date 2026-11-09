from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import config
from .protocol import b64u, generate_keypair, unb64u

SERVICE = "hermes-hands"
logger = logging.getLogger(__name__)


def _log_key_load_failure(error: Exception) -> None:
    if sys.stderr is not None:
        return
    path = config.ROOT / "out" / "device.log"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as log:
        log.write(f"Device key loading failed: {type(error).__name__}: {error}\n")
    if os.name != "nt":
        path.chmod(0o600)


def _keyring():
    try:
        import keyring

        return keyring
    except ImportError:
        return None


def get_or_create() -> tuple[bytes, bytes]:
    if config.KEY_PATH.exists():
        try:
            value = json.loads(config.KEY_PATH.read_text(encoding="utf-8-sig"))
            return unb64u(value["private_key"]), unb64u(value["public_key"])
        except Exception as exc:
            _log_key_load_failure(exc)
            raise
    keyring = _keyring()
    if keyring:
        try:
            value = keyring.get_password(SERVICE, "device-private")
        except Exception as exc:
            error = RuntimeError("Could not read the device key from the keyring; refusing to create a new device identity")
            _log_key_load_failure(error)
            raise error from exc
        if value:
            try:
                private = unb64u(value)
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from cryptography.hazmat.primitives import serialization

                public = Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                return private, public
            except Exception as exc:
                _log_key_load_failure(exc)
                raise
    private, public = generate_keypair()
    if keyring:
        try:
            keyring.set_password(SERVICE, "device-private", b64u(private))
        except Exception:
            logger.warning("Keyring unavailable; using protected device key file")
            keyring = None
    if not keyring:
        config.ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        value = json.dumps({"private_key": b64u(private), "public_key": b64u(public)})
        if os.name == "nt":
            icacls = shutil.which("icacls")
            if not icacls:
                raise RuntimeError("icacls is required to protect the device key")
            whoami = os.path.join(os.environ["SystemRoot"], "System32", "whoami.exe")
            sid_output = subprocess.run([whoami, "/user", "/fo", "csv", "/nh"], check=True, capture_output=True).stdout
            sid_match = re.search(rb"S-1-\d+(?:-\d+)+", sid_output)
            if not sid_match:
                raise RuntimeError("could not determine the current user's SID")
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=config.ROOT, suffix=".tmp", delete=False) as temp_file:
                temp_file.write(value)
                temp_path = Path(temp_file.name)
            try:
                subprocess.run([icacls, str(temp_path), "/inheritance:r", "/grant:r", f"*{sid_match.group().decode('ascii')}:F"], check=True, capture_output=True)
                os.replace(temp_path, config.KEY_PATH)
            except (OSError, subprocess.SubprocessError) as exc:
                temp_path.unlink(missing_ok=True)
                config.KEY_PATH.unlink(missing_ok=True)
                raise RuntimeError("could not protect the device key with icacls") from exc
        else:
            config.KEY_PATH.write_text(value, encoding="utf-8")
            config.KEY_PATH.chmod(0o600)
    return private, public


def remove() -> None:
    config.KEY_PATH.unlink(missing_ok=True)
    keyring = _keyring()
    if keyring:
        try:
            if keyring.get_password(SERVICE, "device-private") is not None:
                keyring.delete_password(SERVICE, "device-private")
        except Exception:
            logger.warning("Keyring unavailable while removing device key")
