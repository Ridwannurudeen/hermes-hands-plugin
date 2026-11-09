from pathlib import Path

from hermeshands_device import protocol as p


def test_sign_verify_tamper_and_wrong_key():
    private, public = p.generate_keypair()
    other_private, other_public = p.generate_keypair()
    signature = p.sign(private, b"message")
    assert p.verify(public, signature, b"message")
    assert not p.verify(public, signature, b"changed")
    assert not p.verify(other_public, signature, b"message")
    assert not p.verify(public, b"bad", b"message")
    assert p.sign(other_private, b"message") != signature


def test_bearer_round_trip_and_malformed_inputs():
    private, _ = p.generate_keypair()
    nonce = p.new_nonce()
    token = p.make_bearer("device-1", private, ts=123, nonce=nonce)
    parsed = p.parse_bearer(token)
    assert parsed and (parsed.device_id, parsed.ts, parsed.nonce) == ("device-1", 123, nonce)
    assert p.verify(p.generate_keypair()[1], parsed.sig, p.bearer_message(parsed.device_id, parsed.ts, parsed.nonce)) is False
    for malformed in ("", None, "hands1.a.1.x.y", "hands2.a.1.x.y", "hands1.A.1.x.y", "hands1.a.no.x.y", "hands1.a.1.a.y", "hands1.a.1." + nonce + ".***", "hands1.a.1." + nonce + ".AAAA"):
        assert p.parse_bearer(malformed) is None


def test_signed_bearer_and_request_message_stability():
    private, public = p.generate_keypair()
    nonce = p.new_nonce()
    token = p.parse_bearer(p.make_bearer("device-1", private, ts=20, nonce=nonce))
    assert token and p.verify(public, token.sig, p.bearer_message(token.device_id, token.ts, token.nonce))
    expected = b"d2r|20|n|POST|/x|" + __import__("hashlib").sha256(b"{}").hexdigest().encode() + b"|hands/1"
    assert p.request_message(p.D2R, 20, "n", "post", "/x", b"{}") == expected
    sig = p.sign_request(private, p.D2R, 20, "n", "POST", "/x", b"{}")
    assert p.verify_request(public, sig, p.D2R, 20, "n", "POST", "/x", b"{}")
    assert not p.verify_request(public, sig, p.D2R, 20, "n", "POST", "/x", b"[]")


def test_freshness_nonce_cache_and_canonical_json():
    assert p.fresh(100, 400)
    assert not p.fresh(99, 400)
    cache = p.NonceCache(ttl=3, max_entries=3)
    assert cache.check_and_add("n", 10)
    assert not cache.check_and_add("n", 11)
    assert cache.check_and_add("n", 13)
    assert p.canonical_json({"é": 1, "a": [2]}) == '{"a":[2],"é":1}'.encode()


def test_protocol_copies_identical():
    repo = Path(__file__).parents[2]
    assert (repo / "hermes-hands/hands/protocol.py").read_bytes() == (repo / "device/hermeshands_device/protocol.py").read_bytes()
