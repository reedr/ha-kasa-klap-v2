"""Use KLAP v2 for Kasa IOT devices that advertise login version 2.

Some older Kasa ("IOT") plugs and switches, such as the EP10 on firmware 1.1.1
Build 250908, keep the legacy command set after a firmware update but switch
their KLAP login to version 2 (sha256 hashing). python-kasa 0.10.2 maps every
``IOT.KLAP`` device to the v1 ``KlapTransport`` (md5 hashing), so the handshake
never matches and the TP-Link integration reports invalid credentials even
when they are right.

This wraps ``kasa.device_factory.get_protocol`` (and the copy ``kasa.discover``
imported) so those devices get ``KlapTransportV2`` instead, the same change as
python-kasa PR #1731. Every other device is left alone. Remove it once a
python-kasa release with that fix reaches Home Assistant.

The v2 transport used is ``GuardedKlapTransportV2`` (see ``transport.py``),
which also logs replies that fail to decrypt and backs off from a plug after
repeated decrypt failures instead of re-handshaking it on every poll.

TP-Link always sets its devices up before this integration (it is our
dependency), so at startup the affected devices are tried with KLAP v1 and fail
authentication. TP-Link then deletes the device's stored credential hash, and
nothing could log in again without the TP-Link password. To survive that, this
integration keeps its own copy of every TP-Link entry's credential hash, puts
it back when TP-Link has dropped it, and reloads the entry.
"""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any

from homeassistant.config_entries import (
    SIGNAL_CONFIG_ENTRY_CHANGED,
    SOURCE_REAUTH,
    ConfigEntry,
    ConfigEntryChange,
    ConfigEntryState,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.storage import Store

from .const import (
    CONF_CREDENTIALS_HASH,
    DOMAIN,
    ISSUE_INCOMPATIBLE,
    ISSUE_NOT_NEEDED,
    STORAGE_KEY,
    STORAGE_VERSION,
    TPLINK_DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

# The unpatched function, kept on the wrapper so it can always be found again.
_ORIGINAL = "_kasa_klap_v2_original"


def _modules() -> tuple[Any, Any]:
    from kasa import device_factory, discover

    return device_factory, discover


def _original(func: Any) -> Any:
    return getattr(func, _ORIGINAL, func)


def _library_state() -> str:
    """Return "patch", "not_needed" or "incompatible" for the installed python-kasa."""
    try:
        from kasa import DeviceConfig
        from kasa.deviceconfig import (
            DeviceConnectionParameters,
            DeviceEncryptionType,
            DeviceFamily,
        )
        from kasa.protocols import IotProtocol
        from kasa.transports import KlapTransport, KlapTransportV2

        device_factory, _ = _modules()
        original = _original(device_factory.get_protocol)
        if not {"config", "strict"} <= set(inspect.signature(original).parameters):
            return "incompatible"
        config = DeviceConfig(
            host="127.0.0.1",
            connection_type=DeviceConnectionParameters(
                DeviceFamily.IotSmartPlugSwitch,
                DeviceEncryptionType.Klap,
                login_version=2,
            ),
        )
        protocol = original(config)
    except (ImportError, AttributeError, TypeError, ValueError):
        _LOGGER.exception("Unexpected python-kasa layout")
        return "incompatible"
    if not isinstance(protocol, IotProtocol):
        return "incompatible"
    transport = type(getattr(protocol, "_transport", None))
    if transport is KlapTransportV2:
        return "not_needed"
    if transport is KlapTransport:
        return "patch"
    return "incompatible"


def _wrap(original: Any) -> Any:
    from kasa.deviceconfig import DeviceEncryptionType
    from kasa.protocols import IotProtocol
    from kasa.transports import KlapTransport

    from .transport import GuardedKlapTransportV2

    @functools.wraps(original)
    def get_protocol(config: Any, *, strict: bool = False) -> Any:
        protocol = original(config, strict=strict)
        ctype = config.connection_type
        if (
            isinstance(protocol, IotProtocol)
            and type(protocol._transport) is KlapTransport
            and ctype.encryption_type is DeviceEncryptionType.Klap
            and (ctype.login_version or 0) >= 2
        ):
            _LOGGER.debug(
                "Using KLAP v2 for %s (login version %s)",
                config.host,
                ctype.login_version,
            )
            return IotProtocol(transport=GuardedKlapTransportV2(config=config))
        return protocol

    setattr(get_protocol, _ORIGINAL, original)
    return get_protocol


def _install() -> None:
    device_factory, discover = _modules()
    original = _original(device_factory.get_protocol)
    wrapped = _wrap(original)
    device_factory.get_protocol = wrapped
    if _original(discover.get_protocol) is original:
        discover.get_protocol = wrapped


def _uninstall() -> None:
    for module in _modules():
        module.get_protocol = _original(module.get_protocol)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Patch python-kasa, or explain why not."""
    for issue in (ISSUE_INCOMPATIBLE, ISSUE_NOT_NEEDED):
        ir.async_delete_issue(hass, DOMAIN, issue)
    # Import off the loop; the probe itself builds transports, which need the loop.
    await hass.async_add_import_executor_job(_modules)
    state = _library_state()
    if state != "patch":
        _LOGGER.warning("Not patching python-kasa: %s", state)
        ir.async_create_issue(
            hass,
            DOMAIN,
            ISSUE_INCOMPATIBLE if state == "incompatible" else ISSUE_NOT_NEEDED,
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key=ISSUE_INCOMPATIBLE
            if state == "incompatible"
            else ISSUE_NOT_NEEDED,
        )
        return True
    _install()
    _LOGGER.info(
        "python-kasa now uses KLAP v2 for IOT devices that advertise login version 2"
    )
    restored = await _async_keep_credential_hashes(hass, entry)
    # TP-Link loads first (it's our dependency), so devices that need the patch
    # failed once: retry those waiting to retry, and those whose hash we put back.
    for tplink_entry in hass.config_entries.async_entries(TPLINK_DOMAIN):
        if (
            tplink_entry.state is ConfigEntryState.SETUP_RETRY
            or tplink_entry.entry_id in restored
        ):
            hass.config_entries.async_schedule_reload(tplink_entry.entry_id)
    return True


async def _async_keep_credential_hashes(
    hass: HomeAssistant, entry: ConfigEntry
) -> set[str]:
    """Back up TP-Link credential hashes, restore dropped ones, and follow changes.

    Returns the TP-Link entry IDs whose hash was put back.
    """
    store: Store[dict[str, str]] = Store(hass, STORAGE_VERSION, STORAGE_KEY)
    saved: dict[str, str] = await store.async_load() or {}
    restored: set[str] = set()
    for tplink_entry in hass.config_entries.async_entries(TPLINK_DOMAIN):
        current = tplink_entry.data.get(CONF_CREDENTIALS_HASH)
        backup = saved.get(tplink_entry.entry_id)
        if current:
            saved[tplink_entry.entry_id] = current
        elif backup and tplink_entry.state in (
            ConfigEntryState.SETUP_ERROR,
            ConfigEntryState.SETUP_RETRY,
        ):
            _LOGGER.info(
                "Restoring the credential hash TP-Link dropped for %s",
                tplink_entry.title,
            )
            hass.config_entries.async_update_entry(
                tplink_entry,
                data={**tplink_entry.data, CONF_CREDENTIALS_HASH: backup},
            )
            # The failed login opened a re-authenticate flow; it is not needed.
            for flow in hass.config_entries.flow.async_progress_by_handler(
                TPLINK_DOMAIN,
                match_context={
                    "source": SOURCE_REAUTH,
                    "entry_id": tplink_entry.entry_id,
                },
            ):
                hass.config_entries.flow.async_abort(flow["flow_id"])
            restored.add(tplink_entry.entry_id)
    saved = {
        entry_id: value
        for entry_id, value in saved.items()
        if hass.config_entries.async_get_entry(entry_id)
    }
    await store.async_save(saved)

    @callback
    def _changed(change: ConfigEntryChange, changed: ConfigEntry) -> None:
        if changed.domain != TPLINK_DOMAIN:
            return
        if change is ConfigEntryChange.REMOVED:
            if saved.pop(changed.entry_id, None) is not None:
                store.async_delay_save(lambda: saved, 1)
            return
        current = changed.data.get(CONF_CREDENTIALS_HASH)
        if current and saved.get(changed.entry_id) != current:
            saved[changed.entry_id] = current
            store.async_delay_save(lambda: saved, 1)

    entry.async_on_unload(
        async_dispatcher_connect(hass, SIGNAL_CONFIG_ENTRY_CHANGED, _changed)
    )
    return restored


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Put python-kasa's own transport selection back."""
    _uninstall()
    return True
