import sqlite3
import time

import pytest

pytest.importorskip("hermes_cli.dashboard_auth")

from hermes_cli.dashboard_auth import ProviderError, TokenPrincipal, assert_protocol_compliance  # noqa: E402

from hands import auth, protocol, relay, store  # noqa: E402
from hands_fakes import Device, hands_db  # noqa: E402,F401  (fixture)

SEED = "cd" * 32


@pytest.fixture
def provider(hands_db):
    return auth.HandsTokenProvider(relay.derive_keys(SEED))


def bearer(device, *, ts=None, private=None, nonce=None):
    return protocol.make_bearer(
        device.device_id,
        private or device.private,
        ts=int(time.time()) if ts is None else ts,
        nonce=nonce or protocol.new_nonce(),
    )


def test_protocol_compliance_and_flags():
    assert_protocol_compliance(auth.HandsTokenProvider)
    cls = auth.HandsTokenProvider
    assert (cls.name, cls.display_name) == ("hermes-hands", "Hermes Hands")
    assert cls.supports_token and not cls.supports_session and not cls.interactive_login
    provider = cls(None)
    assert provider.verify_session(access_token="x") is None
    assert provider.revoke_session(refresh_token="x") is None
    with pytest.raises(NotImplementedError):
        provider.start_login(redirect_uri="https://example.test/cb")


def test_device_bearer_is_verified_but_its_nonce_is_left_to_the_relay(provider):
    device = Device()
    token = bearer(device)
    principal = TokenPrincipal(
        principal=device.device_id, provider="hermes-hands", scopes=(relay.SCOPE_DEVICE,)
    )
    assert provider.verify_token(token=token) == principal
    # Not burned here: the relay burns it once the request signature verified (test_relay).
    assert provider.verify_token(token=token) == principal


def test_stale_or_forged_bearer_is_refused(provider):
    device = Device()
    assert provider.verify_token(token=bearer(device, ts=int(time.time()) - 301)) is None
    other_private, _ = protocol.generate_keypair()
    assert provider.verify_token(token=bearer(device, private=other_private)) is None
    nonce = protocol.new_nonce()
    assert provider.verify_token(token=bearer(device, private=other_private, nonce=nonce)) is None
    assert (
        provider.verify_token(token=bearer(device, nonce=nonce)) is not None
    )  # a forgery burns nothing


def test_only_a_revoked_key_gets_the_revoked_scope(provider):
    device = Device()
    store.revoke("laptop")
    assert provider.verify_token(token=bearer(device)) == TokenPrincipal(
        principal=device.device_id, provider="hermes-hands", scopes=(relay.SCOPE_REVOKED,)
    )
    other_private, _ = protocol.generate_keypair()
    assert provider.verify_token(token=bearer(device, private=other_private)) is None
    assert provider.verify_token(token=bearer(device, ts=int(time.time()) - 301)) is None


def test_unknown_or_unverifiable_device_bearers_get_no_principal(provider):
    """C12: core's seam lets any principal through every token route, so nothing Hands cannot
    verify may get one (the gateway drain bypass)."""
    forged = "hands1.attacker.0.AAAAAAAAAAAAAAAAAAAAAA." + "A" * 86
    assert protocol.parse_bearer(forged) is not None
    assert provider.verify_token(token=forged) is None
    never_paired = Device()
    never_paired.device_id = "0123456789abcdef"
    assert provider.verify_token(token=bearer(never_paired)) is None


def test_pairing_code_until_used(provider):
    code = store.mint_pairing_code("laptop")
    assert provider.verify_token(token=code) == TokenPrincipal(
        principal="pairing:laptop", provider="hermes-hands", scopes=(relay.SCOPE_PAIR,)
    )
    store.complete_pairing(
        code, name="laptop", public_key="AA", os="Linux", home="/h", policy_hash="p"
    )
    assert provider.verify_token(token=code) is None


def test_local_bearer_and_garbage(provider):
    local = provider.verify_token(token=relay.derive_keys(SEED).local_bearer)
    assert local == TokenPrincipal(
        principal="local", provider="hermes-hands", scopes=(relay.SCOPE_LOCAL,)
    )
    assert provider.verify_token(token=relay.derive_keys("ef" * 32).local_bearer) is None
    assert provider.verify_token(token="hands1.not.a.bearer") is None
    assert provider.verify_token(token="") is None


def test_store_outage_is_a_provider_error(provider, monkeypatch):
    def broken(code):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "pairing_code_name", broken)
    with pytest.raises(ProviderError):
        provider.verify_token(token="some-pairing-code")


def test_without_seed_every_token_is_refused(hands_db):
    provider = auth.HandsTokenProvider(None)
    assert provider.verify_token(token=relay.derive_keys(SEED).local_bearer) is None
    assert provider.verify_token(token=store.mint_pairing_code("laptop")) is None
