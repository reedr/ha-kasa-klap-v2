"""Fixtures for Kasa KLAP v2 tests."""

from __future__ import annotations

import pytest
from homeassistant.core import HomeAssistant
from kasa import device_factory, discover

pytest_plugins = ("pytest_homeassistant_custom_component",)


@pytest.fixture(autouse=True)
def enable_integration(enable_custom_integrations):
    """Allow Home Assistant to load the custom integration under test."""


@pytest.fixture(autouse=True)
def no_tplink_setup(hass: HomeAssistant):
    """The dependency on tplink is only for its requirements."""
    hass.config.components.add("tplink")


@pytest.fixture(autouse=True)
def restore_get_protocol():
    """Never leak a patched get_protocol between tests."""
    originals = (device_factory.get_protocol, discover.get_protocol)
    yield
    device_factory.get_protocol, discover.get_protocol = originals
