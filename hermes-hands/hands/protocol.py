"""Pure signing and wire-format helpers shared with the device agent."""

from __future__ import annotations

import base64
import hashlib
import heapq
import json
import re
import secrets
import threading
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTOCOL_VERSION = "hands/1"
D2R = "d2r"
R2D = "r2d"
_DEVICE_ID = re.compile(r"^[a-z0-9-]{1,40}$")
_B64U = re.compile(r"^[A-Za-z0-9_-]+$")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    if not isinstance(text, str) or not text or not _B64U.fullmatch(text):
        raise ValueError("invalid base64url")
    decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(decoded) != text:
        raise ValueError("non-canonical base64url")
    return decoded


def generate_keypair() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    return (
        private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    )


def sign(private_raw: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(private_raw).sign(message)


def verify(public_raw: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def new_nonce() -> str:
    return b64u(secrets.token_bytes(16))


def fresh(ts: int, now: int, window: int = 300) -> bool:
    return isinstance(ts, int) and not isinstance(ts, bool) and isinstance(now, int) and abs(now - ts) <= window


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bearer_message(device_id: str, ts: int, nonce: str) -> bytes:
    return f"{device_id}|{ts}|{nonce}|{PROTOCOL_VERSION}".encode("utf-8")


def make_bearer(device_id: str, private_raw: bytes, *, ts: int, nonce: str) -> str:
    if not _DEVICE_ID.fullmatch(device_id) or len(unb64u(nonce)) != 16:
        raise ValueError("invalid bearer fields")
    return f"hands1.{device_id}.{ts}.{nonce}.{b64u(sign(private_raw, bearer_message(device_id, ts, nonce)))}"


@dataclass(frozen=True)
class Bearer:
    device_id: str
    ts: int
    nonce: str
    sig: bytes


def parse_bearer(token: str) -> Bearer | None:
    try:
        if not isinstance(token, str):
            return None
        parts = token.split(".")
        if len(parts) != 5 or parts[0] != "hands1":
            return None
        _, device_id, ts_text, nonce, sig_text = parts
        if not _DEVICE_ID.fullmatch(device_id) or not ts_text.isascii() or not ts_text.isdecimal() or str(int(ts_text)) != ts_text:
            return None
        if not nonce or not _B64U.fullmatch(nonce) or len(unb64u(nonce)) != 16:
            return None
        sig = unb64u(sig_text)
        if len(sig) != 64:
            return None
        return Bearer(device_id, int(ts_text), nonce, sig)
    except (ValueError, TypeError, OverflowError):
        return None


def request_message(direction: str, ts: int, nonce: str, method: str, path: str, body: bytes) -> bytes:
    return "|".join((direction, str(ts), nonce, method.upper(), path, hashlib.sha256(body).hexdigest(), PROTOCOL_VERSION)).encode("utf-8")


def sign_request(private_raw: bytes, direction, ts, nonce, method, path, body) -> str:
    return b64u(sign(private_raw, request_message(direction, ts, nonce, method, path, body)))


def verify_request(public_raw: bytes, sig_b64u: str, direction, ts, nonce, method, path, body) -> bool:
    try:
        sig = unb64u(sig_b64u)
        return len(sig) == 64 and verify(public_raw, sig, request_message(direction, ts, nonce, method, path, body))
    except (ValueError, TypeError, AttributeError):
        return False


class NonceCache:
    def __init__(self, ttl: int = 600, max_entries: int = 100_000):
        self.ttl = ttl
        self.max_entries = max_entries
        self._entries: dict[str, int] = {}
        self._expiries: list[tuple[int, str]] = []  # a heap holding exactly the entries of _entries
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str, now: int) -> bool:
        with self._lock:
            # Kept through its expiry second: a bearer is fresh for 300 s either side, so a nonce first
            # seen at ts - 300 must still be held at ts + 300 (ttl 600).
            while self._expiries and self._expiries[0][0] < now:
                del self._entries[heapq.heappop(self._expiries)[1]]
            if nonce in self._entries:
                return False
            if len(self._entries) >= self.max_entries:
                del self._entries[heapq.heappop(self._expiries)[1]]
            self._entries[nonce] = now + self.ttl
            heapq.heappush(self._expiries, (now + self.ttl, nonce))
            return True


def policy_hash(policy_bytes: bytes) -> str:
    return hashlib.sha256(policy_bytes).hexdigest()
