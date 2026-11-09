from __future__ import annotations

import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .protocol import b64u, canonical_json, sign, unb64u, verify

_PAYLOAD_FIELDS = (
    "schema_version",
    "device_id",
    "instance",
    "started_at",
    "ended_at",
    "end_reason",
    "shutdown_delivery",
    "events",
)
_EVENT_FIELDS = (
    "timestamp",
    "label",
    "outcome",
    "delivery_status",
    "request_id",
    "checkup",
)


class ReceiptError(ValueError):
    pass


def _receipt_payload(payload: dict, public_key: bytes) -> dict:
    normalized = {key: payload[key] for key in _PAYLOAD_FIELDS if key in payload}
    if normalized.get("schema_version") != 1 or isinstance(normalized.get("schema_version"), bool):
        raise ValueError("unsupported receipt schema")
    if any(not isinstance(normalized.get(key), str) for key in _PAYLOAD_FIELDS[1:7]):
        raise ValueError("invalid receipt metadata")
    events = normalized.get("events")
    if not isinstance(events, list):
        raise ValueError("invalid receipt events")
    normalized["events"] = [
        {key: event[key] for key in _EVENT_FIELDS if key in event}
        for event in events
    ]
    for event in normalized["events"]:
        if not all(isinstance(event.get(key), str) for key in ("timestamp", "label", "outcome")):
            raise ValueError("invalid receipt event")
    normalized["public_key"] = b64u(public_key)
    return normalized


def _encoded_receipt(payload: dict, private_key: bytes, public_key: bytes) -> tuple[dict, str]:
    signed_payload = _receipt_payload(payload, public_key)
    message = canonical_json(signed_payload)
    signature = sign(private_key, message)
    if not verify(public_key, signature, message):
        raise ValueError("receipt signing key does not match its public key")
    envelope = {"payload": signed_payload, "signature": b64u(signature)}
    json_text = json.dumps(envelope, ensure_ascii=False, indent=2) + "\n"
    return signed_payload, json_text


def _text_receipt(payload: dict) -> str:
    lines = [
        "Hermes Hands session receipt",
        f"Device: {payload['device_id']}",
        f"Started: {payload['started_at']}",
        f"Ended: {payload['ended_at']}",
        f"End reason: {payload['end_reason']}",
        f"Final relay heartbeat: {payload['shutdown_delivery']}",
        "Steps:",
    ]
    for event in payload["events"]:
        line = f"[{event['timestamp']}] {event['label']}: {event['outcome']}"
        if "delivery_status" in event:
            line += f" (delivery: {event['delivery_status']})"
        lines.append(line)
        checkup = event.get("checkup")
        if checkup is None:
            continue
        for fact in checkup.get("facts", []):
            value = json.dumps(fact.get("value"), ensure_ascii=False)
            unit = f" {fact['unit']}" if fact.get("unit") else ""
            state = f"{fact.get('status', 'unknown')}/{fact.get('availability', 'unknown')}"
            lines.append(
                f"  Fact {fact.get('id', 'unknown')} ({fact.get('label', 'unknown')}): "
                f"{value}{unit} [{state}] from {fact.get('source', 'unknown')}"
            )
        for inference in checkup.get("inferences", []):
            evidence = ", ".join(inference.get("evidence_ids", []))
            lines.append(
                f"  Inference ({inference.get('confidence', 'unknown')}): "
                f"{inference.get('claim', '')} [evidence: {evidence}]"
            )
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, content: str) -> None:
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)
        if os.name != "nt":
            temporary_path.chmod(0o600)
        os.replace(temporary_path, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_pair(paths: tuple[Path, Path], payload: dict, private_key: bytes, public_key: bytes) -> None:
    signed_payload, json_text = _encoded_receipt(payload, private_key, public_key)
    json_path, text_path = paths
    _atomic_write(json_path, json_text)
    _atomic_write(text_path, _text_receipt(signed_payload))


def write_receipt(payload: dict, private_key: bytes, public_key: bytes) -> tuple[Path, Path]:
    config.ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = config.ROOT / "receipts"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        config.ROOT.chmod(0o700)
        directory.chmod(0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    basename = f"session-{timestamp}-{secrets.token_hex(4)}"
    paths = (directory / f"{basename}.json", directory / f"{basename}.txt")
    _write_pair(paths, payload, private_key, public_key)
    return paths


def update_receipt(
    paths: tuple[Path, Path], payload: dict, private_key: bytes, public_key: bytes
) -> None:
    _write_pair(paths, payload, private_key, public_key)


def verify_receipt(path: str | Path) -> dict:
    try:
        envelope = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("could not read JSON receipt") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ReceiptError("invalid receipt envelope")
    payload = envelope["payload"]
    signature_text = envelope["signature"]
    if not isinstance(payload, dict) or "signature" in payload or not isinstance(signature_text, str):
        raise ReceiptError("invalid receipt envelope")
    if payload.get("schema_version") != 1 or isinstance(payload.get("schema_version"), bool):
        raise ReceiptError("unsupported receipt schema")
    public_key_text = payload.get("public_key")
    if not isinstance(public_key_text, str):
        raise ReceiptError("receipt has no public key")
    try:
        public_key = unb64u(public_key_text)
        signature = unb64u(signature_text)
    except ValueError as exc:
        raise ReceiptError("receipt signature is malformed") from exc
    if len(public_key) != 32 or len(signature) != 64:
        raise ReceiptError("receipt signature is malformed")
    if not verify(public_key, signature, canonical_json(payload)):
        raise ReceiptError("signature does not match the receipt payload")
    return payload
