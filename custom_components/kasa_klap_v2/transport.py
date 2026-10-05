"""KLAP v2 transport with decrypt-failure diagnostics and back-off.

EP10 plugs on firmware 1.1.2 Build 260923 drift into a state where every fresh
KLAP handshake succeeds but the reply to the first query cannot be decrypted
("The length of the provided data is not a multiple of the block length").
python-kasa resets the transport on that error, so the next poll (every few
seconds) performs another full handshake. Over hours the plug gets worse until
it stops answering at all and only a power cycle brings it back.

This transport does two things on top of ``KlapTransportV2``:

* when a reply fails to decrypt, it logs what the plug actually sent (length,
  block alignment, the first bytes in hex, and a text preview if it is
  printable), so the failure mode can be identified;
* after consecutive decrypt failures it refuses to contact the plug for an
  exponentially growing interval instead of re-handshaking on every poll. The
  first good reply clears the back-off.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from kasa.exceptions import KasaException
from kasa.transports import KlapTransportV2

_LOGGER = logging.getLogger(__name__)

BACKOFF_FIRST_SECONDS = 15
BACKOFF_MAX_SECONDS = 600
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


def backoff_seconds(failures: int) -> float:
    """Seconds to leave a plug alone after this many consecutive decrypt failures."""
    if failures <= 0:
        return 0
    return min(BACKOFF_FIRST_SECONDS * 2 ** (failures - 1), BACKOFF_MAX_SECONDS)


class GuardedKlapTransportV2(KlapTransportV2):
    """KlapTransportV2 that explains decrypt failures and backs off after them."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._decrypt_failures = 0
        self._backoff_until = 0.0
        self._skipped = 0

    async def perform_handshake2(self, *args: Any, **kwargs: Any) -> Any:
        session = await super().perform_handshake2(*args, **kwargs)
        decrypt = session.decrypt
        host = self._host

        def logged_decrypt(msg: bytes) -> str:
            try:
                return decrypt(msg)
            except Exception as ex:
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
        now = time.monotonic()
        if now < self._backoff_until:
            self._skipped += 1
            raise KasaException(
                f"Device {self._host} is in decrypt back-off for another "
                f"{self._backoff_until - now:.0f} s"
            )
        try:
            result = await super().send(request)
        except KasaException as ex:
            if "Error trying to decrypt" not in str(ex):
                raise
            self._decrypt_failures += 1
            wait = backoff_seconds(self._decrypt_failures)
            self._backoff_until = time.monotonic() + wait
            _LOGGER.warning(
                "%s: decrypt failure %s in a row; not contacting it for %.0f s",
                self._host,
                self._decrypt_failures,
                wait,
            )
            raise
        if self._decrypt_failures:
            _LOGGER.warning(
                "%s answered normally again after %s decrypt failures "
                "(%s polls skipped during back-off)",
                self._host,
                self._decrypt_failures,
                self._skipped,
            )
            self._decrypt_failures = 0
            self._skipped = 0
            self._backoff_until = 0.0
        return result
