"""Transport selection, a real KLAP v2 handshake, and the safety checks."""

from __future__ import annotations

import os

import pytest
from aiohttp import web
from homeassistant.config_entries import SOURCE_USER, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import issue_registry as ir
from kasa import (
    AuthenticationError,
    Credentials,
    DeviceConfig,
    device_factory,
    discover,
)
from kasa.deviceconfig import (
    DeviceConnectionParameters,
    DeviceEncryptionType,
    DeviceFamily,
)
from kasa.transports import KlapTransport, KlapTransportV2, XorTransport
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.kasa_klap_v2.const import DOMAIN
from custom_components.kasa_klap_v2.transport import GuardedKlapTransportV2

ORIGINAL = device_factory.get_protocol
CREDS = Credentials("Someone+kasa@example.com", "s3cret!")


def _config(
    encryption: DeviceEncryptionType, login_version: int | None, port: int | None = None
) -> DeviceConfig:
    return DeviceConfig(
        host="127.0.0.1",
        port_override=port,
        credentials=CREDS,
        connection_type=DeviceConnectionParameters(
            DeviceFamily.IotSmartPlugSwitch, encryption, login_version=login_version
        ),
    )


def _transport(get_protocol, config: DeviceConfig) -> type:
    return type(get_protocol(config)._transport)


async def _setup(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(domain=DOMAIN, title="Kasa KLAP v2")
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def test_transport_selection(hass: HomeAssistant) -> None:
    """Only IOT.KLAP with login version 2 changes, in both modules, until unload."""
    v2 = _config(DeviceEncryptionType.Klap, 2)
    assert (
        _transport(device_factory.get_protocol, v2) is KlapTransport
    )  # the library bug

    entry = await _setup(hass)
    for module in (device_factory, discover):
        assert _transport(module.get_protocol, v2) is GuardedKlapTransportV2
        assert (
            _transport(module.get_protocol, _config(DeviceEncryptionType.Klap, 1))
            is KlapTransport
        )
        assert (
            _transport(module.get_protocol, _config(DeviceEncryptionType.Klap, None))
            is KlapTransport
        )
        assert (
            _transport(module.get_protocol, _config(DeviceEncryptionType.Xor, None))
            is XorTransport
        )
    assert device_factory.get_protocol(v2, strict=True) is not None

    assert await hass.config_entries.async_unload(entry.entry_id)
    assert device_factory.get_protocol is ORIGINAL
    assert discover.get_protocol is ORIGINAL


async def _fake_v2_plug(aiohttp_server) -> int:
    """A plug that only accepts the KLAP v2 (sha256/sha1) hash of CREDS."""
    auth_hash = KlapTransportV2.generate_auth_hash(CREDS)
    remote_seed = os.urandom(16)
    state: dict[str, bytes] = {}

    async def handshake1(request: web.Request) -> web.Response:
        state["local_seed"] = await request.read()
        server_hash = KlapTransportV2.handshake1_seed_auth_hash(
            state["local_seed"], remote_seed, auth_hash
        )
        return web.Response(body=remote_seed + server_hash)

    async def handshake2(request: web.Request) -> web.Response:
        expected = KlapTransportV2.handshake2_seed_auth_hash(
            state["local_seed"], remote_seed, auth_hash
        )
        return web.Response(status=200 if await request.read() == expected else 403)

    app = web.Application()
    app.router.add_post("/app/handshake1", handshake1)
    app.router.add_post("/app/handshake2", handshake2)
    server = await aiohttp_server(app)
    return server.port


async def test_v2_handshake(
    hass: HomeAssistant, aiohttp_server, socket_enabled
) -> None:
    """Correct credentials fail against a v2 plug without the patch and work with it."""
    port = await _fake_v2_plug(aiohttp_server)
    config = _config(DeviceEncryptionType.Klap, 2, port)

    protocol = device_factory.get_protocol(config)
    with pytest.raises(AuthenticationError, match="did not match our challenge"):
        await protocol._transport.perform_handshake()
    await protocol.close()

    await _setup(hass)
    protocol = device_factory.get_protocol(config)
    await protocol._transport.perform_handshake()
    assert protocol._transport._handshake_done
    await protocol.close()


async def test_not_needed(hass: HomeAssistant) -> None:
    """A python-kasa that already picks v2 gets a repair and is left alone."""

    def fixed(config, *, strict=False):
        protocol = ORIGINAL(config, strict=strict)
        if config.connection_type.login_version == 2:
            from kasa.protocols import IotProtocol

            return IotProtocol(transport=KlapTransportV2(config=config))
        return protocol

    device_factory.get_protocol = fixed
    await _setup(hass)
    assert device_factory.get_protocol is fixed
    assert ir.async_get(hass).async_get_issue(DOMAIN, "not_needed")


async def test_incompatible(hass: HomeAssistant) -> None:
    """A changed signature gets a repair and is left alone."""

    def changed(config):
        return ORIGINAL(config)

    device_factory.get_protocol = changed
    await _setup(hass)
    assert device_factory.get_protocol is changed
    assert ir.async_get(hass).async_get_issue(DOMAIN, "incompatible")


async def test_reload_does_not_stack(hass: HomeAssistant) -> None:
    entry = await _setup(hass)
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert device_factory.get_protocol._kasa_klap_v2_original is ORIGINAL
    assert not ir.async_get(hass).async_get_issue(DOMAIN, "not_needed")
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert device_factory.get_protocol is ORIGINAL


async def test_retries_waiting_tplink_entries(hass: HomeAssistant) -> None:
    """TP-Link entries stuck in setup retry are reloaded once the patch is in."""
    waiting = MockConfigEntry(domain="tplink", title="EP10")
    waiting.add_to_hass(hass)
    waiting.mock_state(hass, ConfigEntryState.SETUP_RETRY)
    idle = MockConfigEntry(domain="tplink", title="KS200")
    idle.add_to_hass(hass)
    idle.mock_state(hass, ConfigEntryState.NOT_LOADED)

    reloaded: list[str] = []
    hass.config_entries.async_schedule_reload = reloaded.append
    await _setup(hass)
    assert reloaded == [waiting.entry_id]


async def test_config_flow(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.ABORT
