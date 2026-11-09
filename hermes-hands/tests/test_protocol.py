import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from hands import protocol


def test_sign_verify_tamper_and_wrong_key():
    private, public = protocol.generate_keypair()
    _, other_public = protocol.generate_keypair()
    sig = protocol.sign(private, b"payload")
    assert protocol.verify(public, sig, b"payload")
    assert not protocol.verify(public, sig, b"tampered")
    assert not protocol.verify(other_public, sig, b"payload")
    assert not protocol.verify(public, b"invalid", b"payload")


def test_bearer_round_trip_and_malformed_values():
    private, public = protocol.generate_keypair()
    nonce = protocol.new_nonce()
    parsed = protocol.parse_bearer(protocol.make_bearer("device-1", private, ts=123, nonce=nonce))
    assert parsed is not None
    assert parsed.device_id == "device-1" and parsed.ts == 123 and parsed.nonce == nonce
    assert protocol.verify(public, parsed.sig, protocol.bearer_message(parsed.device_id, parsed.ts, parsed.nonce))
    for token in ("", None, "hands2.a.1.x.y", "hands1.A.1.x.y", "hands1.a.01.x.y", "hands1.a.bad.x.y", "hands1.a.1.a.y", "hands1.a.1." + nonce + ".***", "hands1.a.1." + nonce + ".AAAA"):
        assert protocol.parse_bearer(token) is None


def test_request_signatures_are_bound_to_all_fields():
    private, public = protocol.generate_keypair()
    body, nonce = b'{"x":1}', protocol.new_nonce()
    sig = protocol.sign_request(private, protocol.D2R, 42, nonce, "post", "/api/x", body)
    assert protocol.verify_request(public, sig, protocol.D2R, 42, nonce, "POST", "/api/x", body)
    assert not protocol.verify_request(public, sig, protocol.D2R, 42, nonce, "POST", "/api/x", b"changed")
    assert protocol.request_message("d2r", 42, "n", "post", "/x", b"{}") == protocol.request_message("d2r", 42, "n", "POST", "/x", b"{}")


def test_freshness_replay_and_canonical_json():
    assert protocol.fresh(100, 400)
    assert not protocol.fresh(99, 400)
    cache = protocol.NonceCache(ttl=600)
    assert cache.check_and_add("n", 1)
    assert not cache.check_and_add("n", 2)
    assert protocol.canonical_json({"é": 1, "a": 2}) == '{"a":2,"é":1}'.encode("utf-8")


def test_protocol_implementations_are_byte_identical():
    repo = Path(__file__).parents[2]
    assert (repo / "hermes-hands/hands/protocol.py").read_bytes() == (repo / "device/hermeshands_device/protocol.py").read_bytes()
