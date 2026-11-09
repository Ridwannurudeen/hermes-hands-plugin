"""``HandsTokenProvider``: the dashboard token-auth seam for pairing codes, device bearers and the
gateway's local bearer (``hermes_cli/dashboard_auth/base.py:92-161``, ``token_auth.py:49-96``).

``verify_token`` sees only the token string, so a device bearer proves identity and freshness here
(signature, 300 s window). Its nonce is burned by the relay only after the request signature also
verified (``relay.Relay._device``), so holding a bearer without the device key cannot burn one. A
fresh bearer signed by a revoked device's key (its tombstone) gets a ``hands:revoked`` principal so
the relay can answer a signed ``401 unknown_device``, which tells the device to stop. Any other
bearer, an unknown device_id included, gets None: core's token seam asks every provider about every
token route and lets any principal through (``token_auth.py:57-86``), so a principal minted for a
token Hands cannot verify would open other plugins' token routes, such as core's drain route. The
same seam means every genuine Hands credential still opens those routes: a paired device's bearer,
a revoked key until the relay has told it to stop (at most ``store.TOMBSTONE_TTL``), a live pairing
code and the gateway's local bearer. Core gives ``verify_token`` no path, so the plugin cannot
narrow that.
"""

from __future__ import annotations

import hmac
import sqlite3
import time
from typing import Optional

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    LoginStart,
    ProviderError,
    Session,
    TokenPrincipal,
)

from . import protocol, store
from .relay import PROVIDER, SCOPE_DEVICE, SCOPE_LOCAL, SCOPE_PAIR, SCOPE_REVOKED, Keys


class HandsTokenProvider(DashboardAuthProvider):
    name = PROVIDER
    display_name = "Hermes Hands"
    supports_token = True
    supports_session = False
    interactive_login = False

    def __init__(self, keys: Keys | None):
        """``keys`` is None until ``hermes hands setup`` has written the seed: every token is refused."""
        self.keys = keys

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        raise NotImplementedError("Hermes Hands authenticates devices by token only")

    def complete_login(
        self, *, code: str, state: str, code_verifier: str, redirect_uri: str
    ) -> Session:
        raise NotImplementedError("Hermes Hands authenticates devices by token only")

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        return None

    def refresh_session(self, *, refresh_token: str) -> Session:
        raise NotImplementedError("Hermes Hands authenticates devices by token only")

    def revoke_session(self, *, refresh_token: str) -> None:
        return None

    def verify_token(self, *, token: str) -> Optional[TokenPrincipal]:
        if self.keys is None:
            return None
        bearer = protocol.parse_bearer(token)
        try:
            if bearer is not None:
                return self._verify_device(bearer)
            if hmac.compare_digest(token.encode("utf-8"), self.keys.local_bearer.encode("utf-8")):
                return TokenPrincipal(principal="local", provider=PROVIDER, scopes=(SCOPE_LOCAL,))
            name = store.pairing_code_name(token)
        except sqlite3.Error as exc:
            raise ProviderError(f"the Hermes Hands device store is unavailable: {exc}") from exc
        if name is None:
            return None
        return TokenPrincipal(principal=f"pairing:{name}", provider=PROVIDER, scopes=(SCOPE_PAIR,))

    def _verify_device(self, bearer: protocol.Bearer) -> Optional[TokenPrincipal]:
        device = store.device_by_id(bearer.device_id)
        if device is not None:
            public_key, scope = device["public_key"], SCOPE_DEVICE
        else:
            public_key, scope = store.revoked_key(bearer.device_id), SCOPE_REVOKED
            if public_key is None:
                return None
        now = int(time.time())
        message = protocol.bearer_message(bearer.device_id, bearer.ts, bearer.nonce)
        if not protocol.fresh(bearer.ts, now) or not protocol.verify(
            public_key, bearer.sig, message
        ):
            return None
        return TokenPrincipal(principal=bearer.device_id, provider=PROVIDER, scopes=(scope,))
