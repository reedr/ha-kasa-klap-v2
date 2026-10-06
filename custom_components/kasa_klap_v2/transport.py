"""KLAP v2 transport with decrypt-failure diagnostics and back-off.

EP10 plugs on firmware 1.1.2 Build 260923 drift into a state where every fresh
KLAP handshake succeeds but the reply to the first query cannot be decrypted
("The length of the provided data is not a multiple of the block length").
python-kasa resets the transport on that error, so the next poll (every few
seconds) performs another full handshake. Over hours the plug gets worse until
it stops answering at all and only a power cycle brings it back.

What the plug sends instead is its generic web page,
``<html><body><center>200 OK</center></body></html>``: it no longer recognises
the session. The likely cause is session exhaustion. Every handshake creates a
session on the plug that lives for 24 hours, and python-kasa starts a new one
after any timeout, so each Wi-Fi blip leaks a session until the plug has no
room for the one it just agreed to.

This transport adds, on top of ``KlapTransportV2``:

* session keeping: after a timeout or connection error the session is kept
  instead of being thrown away, so the next poll reuses it rather than leaking
  another one. A 403, an expired session or a bad reply still starts a new one;
* diagnostics: when a reply fails to decrypt, it logs what the plug actually
  sent (length, block alignment, the first bytes in hex, and a text preview if
  it is printable);
* dropped sessions: the plug also answers with the generic page when it has
  silently dropped a session that was working (seen 2026-10-06: the Theater
  Marquee, after a quiet night). That needs one new login, not a back-off, so a
  page on a session that has already worked triggers one immediate re-login and
  retry. Only a page on a brand-new session counts as a stuck plug;
* back-off: after consecutive decrypt failures it refuses to contact the plug
  for an exponentially growing interval instead of re-handshaking on every
  poll. When the reply is the generic page the wait starts at 30 minutes, so
  old sessions can expire instead of being joined by new ones. The first good
  reply clears the back-off.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from kasa.exceptions import KasaException, _ConnectionError
from kasa.transports import KlapTransportV2

_LOGGER = logging.getLogger(__name__)

BACKOFF_FIRST_SECONDS = 15
BACKOFF_MAX_SECONDS = 600
# When the plug answers with its generic page it has no session for us; give
# its old sessions time to expire.
NO_SESSION_BACKOFF_FIRST_SECONDS = 1800
NO_SESSION_BACKOFF_MAX_SECONDS = 3600
_PREVIEW_BYTES = 48


def describe_response(msg: bytes) -> str:
    """Summarise a KLAP reply that would not decrypt."""
    body = msg[32:]
    parts = [
        f"{len(msg)} bytes",
        f"ciphertext {len(body)} bytes ({len(body) % 16} past a 16-byte block)",
        f"head {msg[:_PREVIEW_BYTES].hex()}",
    ]
    try:
        text = msg.decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:
        if text.isprintable() or all(c.isprintable() or c.isspace() for c in text):
            parts.append(f"text {text[:120]!r}")
    return ", ".join(parts)


def backoff_seconds(failures: int, no_session: bool = False) -> float:
    """Seconds to leave a plug alone after this many consecutive decrypt failures."""
    if failures <= 0:
        return 0
    if no_session:
        return min(
            NO_SESSION_BACKOFF_FIRST_SECONDS * 2 ** (failures - 1),
            NO_SESSION_BACKOFF_MAX_SECONDS,
        )
    return min(BACKOFF_FIRST_SECONDS * 2 ** (failures - 1), BACKOFF_MAX_SECONDS)


def is_network_error(ex: BaseException) -> bool:
    """True for a failure to reach the plug, as opposed to a reply it sent.

    python-kasa's HTTP client raises TimeoutError for timeouts, _ConnectionError
    for dropped connections, and a plain KasaException ("Unable to query the
    device: ...") for anything else that goes wrong in the request itself --
    which, depending on the aiohttp version, includes timeouts.
    """
    if isinstance(ex, (TimeoutError, _ConnectionError)):
        return True
    if not isinstance(ex, KasaException) or not ex.args:
        return False
    # Raised as KasaException(message, cause), so str(ex) is a tuple repr.
    return str(ex.args[0]).startswith("Unable to query the device")


def is_session_page(msg: bytes | None) -> bool:
    """True when a KLAP reply is the plug's generic web page, not ciphertext."""
    return bool(msg) and msg.lstrip()[:5].lower() == b"<html"


@dataclass
class PlugHealth:
    """Decrypt-failure state for one plug.

    Kept per host rather than per transport: Home Assistant builds a new
    transport for every setup attempt, and a fresh transport must not start a
    new handshake (and leak another session) while the plug is backed off.
    """

    failures: int = 0
    backoff_until: float = 0.0
    skipped: int = 0


_HEALTH: dict[str, PlugHealth] = {}


class GuardedKlapTransportV2(KlapTransportV2):
    """KlapTransportV2 that explains decrypt failures and backs off after them."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._health = _HEALTH.setdefault(self._host, PlugHealth())
        self._keep_session = False
        self._last_bad_reply: bytes | None = None
        # Whether the current session has produced a good reply, and its history.
        self._session_good = False
        self._session_started = 0.0
        self._session_replies = 0

    async def perform_handshake(self) -> None:
        await super().perform_handshake()
        self._session_good = False
        self._session_started = time.monotonic()
        self._session_replies = 0

    async def perform_handshake2(self, *args: Any, **kwargs: Any) -> Any:
        session = await super().perform_handshake2(*args, **kwargs)
        decrypt = session.decrypt
        host = self._host

        def logged_decrypt(msg: bytes) -> str:
            try:
                return decrypt(msg)
            except Exception as ex:
                self._last_bad_reply = msg
                _LOGGER.warning(
                    "%s sent a reply that will not decrypt (%s): %s",
                    host,
                    ex,
                    describe_response(msg),
                )
                raise

        session.decrypt = logged_decrypt
        return session

    async def send(self, request: str) -> Any:
        health = self._health
        now = time.monotonic()
        if now < health.backoff_until:
            health.skipped += 1
            raise KasaException(
                f"Device {self._host} is in decrypt back-off for another "
                f"{health.backoff_until - now:.0f} s"
            )
        for attempt in (1, 2):
            self._keep_session = False
            self._last_bad_reply = None
            try:
                result = await super().send(request)
                break
            except (TimeoutError, KasaException) as ex:
                if is_network_error(ex):
                    # Network trouble says nothing about the session; keep it so
                    # the retry does not leak another one on the plug.
                    if self._handshake_done and not self._handshake_session_expired():
                        self._keep_session = True
                    raise
                if "Error trying to decrypt" not in str(ex):
                    raise
                no_session = is_session_page(self._last_bad_reply)
                if no_session and attempt == 1 and self._session_good:
                    # The plug dropped a session that had been working (it
                    # expires them sooner than its TIMEOUT cookie says). One new
                    # login fixes that; no back-off.
                    _LOGGER.warning(
                        "%s dropped our KLAP session after %.0f min and %s good "
                        "replies; logging in again",
                        self._host,
                        (time.monotonic() - self._session_started) / 60,
                        self._session_replies,
                    )
                    self._handshake_done = False
                    continue
                health.failures += 1
                wait = backoff_seconds(health.failures, no_session)
                health.backoff_until = time.monotonic() + wait
                _LOGGER.warning(
                    "%s: decrypt failure %s in a row%s; not contacting it for %.0f s",
                    self._host,
                    health.failures,
                    " (generic page on a fresh session: the plug has no room "
                    "for us, likely out of session slots)"
                    if no_session
                    else "",
                    wait,
                )
                raise
        self._session_good = True
        self._session_replies += 1
        if health.failures:
            _LOGGER.warning(
                "%s answered normally again after %s decrypt failures "
                "(%s polls skipped during back-off)",
                self._host,
                health.failures,
                health.skipped,
            )
            health.failures = 0
            health.skipped = 0
            health.backoff_until = 0.0
        return result

    async def reset(self) -> None:
        """Drop the session, unless the last failure was only network trouble."""
        if self._keep_session:
            self._keep_session = False
            _LOGGER.debug(
                "%s: keeping the KLAP session after a network error", self._host
            )
            return
        await super().reset()

    async def close(self) -> None:
        self._keep_session = False
        await super().close()
