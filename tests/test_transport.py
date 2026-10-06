"""Decrypt-failure diagnostics and back-off in GuardedKlapTransportV2."""

from __future__ import annotations

import asyncio
import json
import logging
import os

import pytest
from aiohttp import web
from kasa import Credentials, DeviceConfig, KasaException
from kasa.deviceconfig import (
    DeviceConnectionParameters,
    DeviceEncryptionType,
    DeviceFamily,
)
from kasa.transports import KlapTransportV2
from kasa.transports.klaptransport import KlapEncryptionSession

from custom_components.kasa_klap_v2 import transport as guarded
from custom_components.kasa_klap_v2.transport import (
    GuardedKlapTransportV2,
    backoff_seconds,
    describe_response,
    is_network_error,
    is_session_page,
)

CREDS = Credentials("Someone+kasa@example.com", "s3cret!")
SESSION_PAGE = b"<html><body><center>200 OK</center></body></html>"


class FakePlug:
    """A KLAP v2 plug whose query replies can be switched between good and broken."""

    def __init__(self) -> None:
        self.auth_hash = KlapTransportV2.generate_auth_hash(CREDS)
        self.remote_seed = os.urandom(16)
        self.local_seed = b""
        self.broken = True
        self.page = False
        self.page_next = 0  # answer this many queries with the page, then recover
        self.delay = 0.0
        self.handshakes = 0
        self.requests = 0

    async def handshake1(self, request: web.Request) -> web.Response:
        self.handshakes += 1
        self.local_seed = await request.read()
        server_hash = KlapTransportV2.handshake1_seed_auth_hash(
            self.local_seed, self.remote_seed, self.auth_hash
        )
        return web.Response(body=self.remote_seed + server_hash)

    async def handshake2(self, request: web.Request) -> web.Response:
        expected = KlapTransportV2.handshake2_seed_auth_hash(
            self.local_seed, self.remote_seed, self.auth_hash
        )
        return web.Response(status=200 if await request.read() == expected else 403)

    async def query(self, request: web.Request) -> web.Response:
        self.requests += 1
        await request.read()
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.page or self.page_next > 0:
            self.page_next = max(0, self.page_next - 1)
            return web.Response(body=SESSION_PAGE)
        if self.broken:
            # 32-byte signature plus a ciphertext that is not block aligned.
            return web.Response(body=os.urandom(32) + b"\x01\x02\x03\x04\x05")
        session = KlapEncryptionSession(
            self.local_seed, self.remote_seed, self.auth_hash
        )
        session._seq = int(request.query["seq"]) - 1
        body, _ = session.encrypt(json.dumps({"system": {"get_sysinfo": {}}}))
        return web.Response(body=body)


@pytest.fixture(autouse=True)
def fresh_health():
    """Back-off state is per host; never carry it between tests."""
    guarded._HEALTH.clear()
    yield
    guarded._HEALTH.clear()


@pytest.fixture
async def plug(aiohttp_server, socket_enabled) -> tuple[FakePlug, int]:
    fake = FakePlug()
    app = web.Application()
    app.router.add_post("/app/handshake1", fake.handshake1)
    app.router.add_post("/app/handshake2", fake.handshake2)
    app.router.add_post("/app/request", fake.query)
    server = await aiohttp_server(app)
    return fake, server.port


def _transport(port: int, timeout: float | None = None) -> GuardedKlapTransportV2:
    return GuardedKlapTransportV2(
        config=DeviceConfig(
            host="127.0.0.1",
            port_override=port,
            timeout=timeout or 5,
            credentials=CREDS,
            connection_type=DeviceConnectionParameters(
                DeviceFamily.IotSmartPlugSwitch,
                DeviceEncryptionType.Klap,
                login_version=2,
            ),
        )
    )


def test_backoff_schedule() -> None:
    assert backoff_seconds(0) == 0
    assert [backoff_seconds(n) for n in range(1, 8)] == [15, 30, 60, 120, 240, 480, 600]
    assert [backoff_seconds(n, no_session=True) for n in range(1, 4)] == [
        1800,
        3600,
        3600,
    ]


def test_is_network_error() -> None:
    assert is_network_error(TimeoutError("timed out"))
    assert is_network_error(KasaException("Unable to query the device: x: ", None))
    assert not is_network_error(KasaException("Error trying to decrypt device x"))
    assert not is_network_error(KasaException("Device x responded with 500"))


def test_is_session_page() -> None:
    assert is_session_page(SESSION_PAGE)
    assert not is_session_page(bytes(49))
    assert not is_session_page(None)


def test_describe_response() -> None:
    assert "37 bytes" in describe_response(bytes(32) + b"\x01\x02\x03\x04\x05")
    assert "5 past a 16-byte block" in describe_response(bytes(37))
    assert "text 'Too many sessions'" in describe_response(b"Too many sessions")


async def test_decrypt_failure_logs_and_backs_off(
    plug, caplog, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake, port = plug
    clock = [1000.0]
    monkeypatch.setattr(guarded.time, "monotonic", lambda: clock[0])
    transport = _transport(port)
    caplog.set_level(logging.WARNING, logger=guarded.__name__)

    with pytest.raises(KasaException, match="Error trying to decrypt"):
        await transport.send('{"system":{"get_sysinfo":{}}}')
    assert "will not decrypt" in caplog.text
    assert "5 past a 16-byte block" in caplog.text
    assert "decrypt failure 1 in a row; not contacting it for 15 s" in caplog.text
    assert (fake.handshakes, fake.requests) == (1, 1)

    # Inside the back-off the plug is not contacted at all, not even a handshake.
    await transport.reset()
    clock[0] += 10
    with pytest.raises(KasaException, match="back-off"):
        await transport.send('{"system":{"get_sysinfo":{}}}')
    assert (fake.handshakes, fake.requests) == (1, 1)

    # Once it expires the next failure doubles the wait.
    clock[0] += 6
    with pytest.raises(KasaException, match="Error trying to decrypt"):
        await transport.send('{"system":{"get_sysinfo":{}}}')
    assert "decrypt failure 2 in a row; not contacting it for 30 s" in caplog.text

    # A good reply clears the back-off.
    await transport.reset()
    fake.broken = False
    clock[0] += 31
    assert await transport.send('{"system":{"get_sysinfo":{}}}') == {
        "system": {"get_sysinfo": {}}
    }
    assert "answered normally again after 2 decrypt failures" in caplog.text
    assert transport._health.failures == 0
    await transport.send('{"system":{"get_sysinfo":{}}}')
    await transport.close()


async def test_other_errors_do_not_back_off(plug) -> None:
    """Only decrypt failures start a back-off."""
    _, port = plug
    transport = _transport(port)
    transport._credentials = Credentials("wrong@example.com", "nope")
    transport._local_auth_hash = KlapTransportV2.generate_auth_hash(
        transport._credentials
    )
    with pytest.raises(KasaException):
        await transport.send('{"system":{"get_sysinfo":{}}}')
    assert transport._health.failures == 0
    assert transport._health.backoff_until == 0.0
    await transport.close()


async def test_generic_page_backs_off_long(
    plug, caplog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plug's generic page means no session for us: wait 30 minutes."""
    fake, port = plug
    clock = [1000.0]
    monkeypatch.setattr(guarded.time, "monotonic", lambda: clock[0])
    fake.page = True
    transport = _transport(port)
    caplog.set_level(logging.WARNING, logger=guarded.__name__)
    with pytest.raises(KasaException, match="Error trying to decrypt"):
        await transport.send('{"system":{"get_sysinfo":{}}}')
    assert "text '<html><body><center>200 OK</center></body></html>'" in caplog.text
    assert "generic page on a fresh session" in caplog.text
    assert "not contacting it for 1800 s" in caplog.text
    assert fake.handshakes == 1
    assert transport._health.backoff_until == 1000.0 + 1800

    # A bad reply still drops the session.
    await transport.reset()
    assert not transport._handshake_done
    await transport.close()


@pytest.mark.parametrize("expected_lingering_timers", [True])
async def test_timeout_keeps_session(plug) -> None:
    """A timed-out query keeps the session, so the retry does not re-handshake."""
    fake, port = plug
    fake.broken = False
    transport = _transport(port, timeout=0.3)
    await transport.send('{"system":{"get_sysinfo":{}}}')
    assert fake.handshakes == 1

    fake.delay = 1.0
    with pytest.raises((TimeoutError, KasaException), match="Unable to query"):
        await transport.send('{"system":{"get_sysinfo":{}}}')
    await transport.reset()  # what IotProtocol does after a timeout
    assert transport._handshake_done

    fake.delay = 0
    await transport.send('{"system":{"get_sysinfo":{}}}')
    assert fake.handshakes == 1

    # A plain reset (any other error) still drops it.
    await transport.reset()
    await transport.send('{"system":{"get_sysinfo":{}}}')
    assert fake.handshakes == 2
    await transport.close()


async def test_backoff_survives_a_new_transport(
    plug, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Home Assistant's setup retries build new transports; the back-off holds."""
    fake, port = plug
    clock = [1000.0]
    monkeypatch.setattr(guarded.time, "monotonic", lambda: clock[0])
    fake.page = True
    first = _transport(port)
    with pytest.raises(KasaException, match="Error trying to decrypt"):
        await first.send('{"system":{"get_sysinfo":{}}}')
    await first.close()
    assert fake.handshakes == 1

    clock[0] += 60
    second = _transport(port)
    with pytest.raises(KasaException, match="back-off"):
        await second.send('{"system":{"get_sysinfo":{}}}')
    assert fake.handshakes == 1
    await second.close()


async def test_dropped_session_logs_in_again(plug, caplog) -> None:
    """A working session the plug drops gets one new login, with no back-off."""
    fake, port = plug
    fake.broken = False
    transport = _transport(port)
    caplog.set_level(logging.WARNING, logger=guarded.__name__)
    await transport.send('{"system":{"get_sysinfo":{}}}')
    assert fake.handshakes == 1

    fake.page_next = 1
    assert await transport.send('{"system":{"get_sysinfo":{}}}') == {
        "system": {"get_sysinfo": {}}
    }
    assert fake.handshakes == 2
    assert "dropped our KLAP session" in caplog.text
    assert transport._health.failures == 0
    assert transport._health.backoff_until == 0.0
    await transport.close()


async def test_page_after_new_login_backs_off(
    plug, caplog, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the fresh login also gets the page, the plug is stuck: back off long."""
    fake, port = plug
    clock = [1000.0]
    monkeypatch.setattr(guarded.time, "monotonic", lambda: clock[0])
    fake.broken = False
    transport = _transport(port)
    caplog.set_level(logging.WARNING, logger=guarded.__name__)
    await transport.send('{"system":{"get_sysinfo":{}}}')

    fake.page = True
    with pytest.raises(KasaException, match="Error trying to decrypt"):
        await transport.send('{"system":{"get_sysinfo":{}}}')
    assert fake.handshakes == 2  # one retry only
    assert "page on a fresh session" in caplog.text
    assert transport._health.backoff_until == 1000.0 + 1800
    await transport.close()
