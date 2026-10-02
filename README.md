# Kasa KLAP v2

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/reedr/ha-kasa-klap-v2)

A stopgap for older Kasa plugs and switches that the built-in **TP-Link Smart Home** integration can no longer log in to
after a firmware update.

Some Kasa "IOT" devices (seen on the EP10(US) with firmware 1.1.1 Build 250908, and reported on the KP115, KS200M and
HS300) keep their legacy command set after a firmware update but switch their KLAP login to **version 2**. Their
discovery reply shows it:

```json
"mgt_encrypt_schm": {"encrypt_type": "KLAP", "new_klap": 1, "lv": 2, "http_port": 80}
```

python-kasa 0.10.2, which Home Assistant pins, uses KLAP v1 (md5 hashing) for every IOT device, so the handshake never
matches. The device goes unavailable, and reconfiguring it fails with "invalid credentials" even when the TP-Link
e-mail and password are right:

```
Device response did not match our challenge on ip 10.0.3.210, check that your e-mail and password (both case-sensitive) are correct.
```

This integration wraps python-kasa's `get_protocol` so IOT devices that advertise KLAP with login version 2 get
`KlapTransportV2` (sha256 hashing) instead. It is the same change as
[python-kasa#1731](https://github.com/python-kasa/python-kasa/pull/1731); see also
[python-kasa#1740](https://github.com/python-kasa/python-kasa/issues/1740) and
[home-assistant/core#177207](https://github.com/home-assistant/core/issues/177207). Every other device is unaffected,
and unloading the integration puts python-kasa's own selection back.

## Setup

1. Install through HACS and restart.
2. **Settings → Devices & services → Add integration → Kasa KLAP v2.**
3. For each affected device, open its TP-Link entry, choose **Reconfigure**, keep its IP address and enter your TP-Link
   (Kasa app) e-mail and password.

TP-Link entries that were waiting to retry are retried as soon as the integration loads.

If the login still fails, the device may hold an old password: it keeps a hash of the account password from its last
cloud sync. Removing the device from the Kasa app and adding it again refreshes it.

## When to remove it

Once a python-kasa release with the fix reaches Home Assistant, a repair says the integration is no longer needed. If
python-kasa changes so the patch no longer fits, a repair says it can't apply its change.

## License

MIT. See [LICENSE](LICENSE).
